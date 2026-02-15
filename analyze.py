import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from collections import Counter

# Настройка стиля для графиков
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

def load_and_prepare_data(file_path):
    """
    Загрузка и подготовка данных из JSON файла
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    # Извлечение результатов в отдельный список
    records = [item['result'] for item in data]
    
    # Создание DataFrame
    df = pd.DataFrame(records)
    
    # Преобразование временной метки
    df['_time'] = pd.to_datetime(df['_time'])
    
    print(f"Загружено записей: {len(df)}")
    print(f"Временной диапазон: {df['_time'].min()} - {df['_time'].max()}")
    
    return df

def analyze_suspicious_windows_events(df):
    """
    Анализ подозрительных событий Windows
    """
    suspicious_events = []
    
    # Словарь для маппинга EventID в описания
    event_descriptions = {
        # Логины и аутентификация
        4624: "Successful Logon",
        4625: "Failed Logon",
        4648: "Logon with Explicit Credentials",
        4672: "Special Privileges Assigned",
        
        # Создание/завершение процессов
        4688: "Process Creation",
        4689: "Process Exit",
        
        # Изменение прав
        4703: "User Right Adjusted",
        4732: "Member Added to Security Group",
        4733: "Member Removed from Security Group",
        
        # Доступ к объектам
        4656: "Object Handle Requested",
        4663: "Object Access Attempt",
        
        # Системные события
        4608: "Windows Startup",
        4609: "Windows Shutdown",
        4616: "System Time Change",
        
        # События безопасности
        4740: "Account Locked Out",
        4768: "Kerberos Ticket Requested",
        4769: "Kerberos Ticket Granted",
        4776: "Credential Validation",
        
        # Удаленные подключения
        5140: "Network Share Object Accessed",
        5156: "Connection Allowed",
        5157: "Connection Denied",
        
        # Службы
        7036: "Service Started/Stopped",
        
        # Специфичные подозрительные
        1102: "Security Log Cleared",
        4720: "User Account Created",
        4726: "User Account Deleted",
        4728: "Member Added to Global Group",
        4735: "Security Group Changed",
        4798: "User Group Membership Enumerated",
    }
    
    # Анализируем каждую запись
    for idx, row in df.iterrows():
        event_id = row.get('EventCode')
        if not event_id:
            continue
            
        try:
            event_id = int(event_id)
        except:
            continue
            
        # Базовые подозрительные события
        suspicious_score = 0
        reasons = []
        
        # Проверка по EventID
        if event_id in [4625, 4648, 4720, 4726, 1102, 4740, 4672]:
            suspicious_score += 3
            reasons.append(f"High-risk event: {event_descriptions.get(event_id, f'Unknown ({event_id})')}")
        
        # Средне-рисковые события
        elif event_id in [4688, 4703, 4656, 4768, 4769, 4732, 4735]:
            suspicious_score += 2
            reasons.append(f"Medium-risk event: {event_descriptions.get(event_id, f'Unknown ({event_id})')}")
        
        # Низко-рисковые, но требующие внимания
        elif event_id in [4624, 4689, 5140, 5156, 7036]:
            suspicious_score += 1
            reasons.append(f"Info event: {event_descriptions.get(event_id, f'Unknown ({event_id})')}")
        
        # Проверка на специфичные признаки
        if event_id == 4688:  # Process Creation
            process_name = row.get('New_Process_Name', '')
            if isinstance(process_name, str):
                # Подозрительные процессы
                suspicious_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32']
                if any(proc in process_name.lower() for proc in suspicious_processes):
                    suspicious_score += 2
                    reasons.append(f"Suspicious process: {process_name}")
        
        elif event_id == 4624:  # Logon
            logon_type = row.get('Logon_Type')
            if logon_type in ['3', '10']:  # Network or Remote Interactive
                suspicious_score += 1
                reasons.append(f"Remote logon (Type {logon_type})")
        
        # Добавляем событие если есть хоть какая-то подозрительность
        if suspicious_score > 0:
            suspicious_events.append({
                'timestamp': row.get('_time'),
                'event_id': event_id,
                'event_name': event_descriptions.get(event_id, f'Event {event_id}'),
                'computer': row.get('ComputerName', 'Unknown'),
                'user': row.get('user', row.get('Account_Name', 'Unknown')),
                'suspicious_score': suspicious_score,
                'reasons': '; '.join(reasons) if reasons else 'Generic suspicious',
                'raw_data': row.to_dict() if suspicious_score >= 3 else None  # Сохраняем raw только для высокорисковых
            })
    
    return pd.DataFrame(suspicious_events)

def create_visualizations(suspicious_df, original_df):
    """
    Создание визуализаций для подозрительных событий
    """
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Analysis of Suspicious Windows Events', fontsize=16, fontweight='bold')
    
    # 1. Топ-10 событий по количеству (все события)
    top_events_all = original_df['EventCode'].value_counts().head(10)
    sns.barplot(x=top_events_all.values, y=top_events_all.index.astype(str), ax=axes[0, 0])
    axes[0, 0].set_title('Top 10 Events by Frequency (All Events)')
    axes[0, 0].set_xlabel('Count')
    
    # 2. Топ-10 подозрительных событий по типу
    if not suspicious_df.empty:
        top_suspicious_types = suspicious_df['event_name'].value_counts().head(10)
        sns.barplot(x=top_suspicious_types.values, y=top_suspicious_types.index, ax=axes[0, 1])
        axes[0, 1].set_title('Top 10 Suspicious Events by Type')
        axes[0, 1].set_xlabel('Count')
    
    # 3. Распределение подозрительных событий по уровню риска
    if not suspicious_df.empty:
        risk_distribution = suspicious_df['suspicious_score'].value_counts().sort_index()
        colors = ['green', 'orange', 'red']
        axes[1, 0].pie(risk_distribution.values, labels=[f"Level {i}" for i in risk_distribution.index], 
                       autopct='%1.1f%%', colors=colors[:len(risk_distribution)])
        axes[1, 0].set_title('Distribution of Suspicious Events by Risk Level')
        axes[1, 0].legend([f"Level {i}: {'High' if i>=3 else 'Medium' if i>=2 else 'Low'}" 
                          for i in risk_distribution.index])
    
    # 4. Топ-10 хостов с подозрительной активностью
    if not suspicious_df.empty:
        top_suspicious_hosts = suspicious_df['computer'].value_counts().head(10)
        sns.barplot(x=top_suspicious_hosts.values, y=top_suspicious_hosts.index, ax=axes[1, 1])
        axes[1, 1].set_title('Top 10 Hosts with Suspicious Activity')
        axes[1, 1].set_xlabel('Number of Suspicious Events')
    
    plt.tight_layout()
    plt.show()
    
    # Дополнительный график для топ-10 самых подозрительных событий
    fig2, ax2 = plt.subplots(figsize=(12, 6))
    
    if not suspicious_df.empty:
        # Комбинируем event_id и event_name для лучшей идентификации
        suspicious_df['event_label'] = suspicious_df['event_id'].astype(str) + ': ' + suspicious_df['event_name']
        top_combined = suspicious_df['event_label'].value_counts().head(10)
        
        sns.barplot(x=top_combined.values, y=top_combined.index, ax=ax2, palette='Reds_d')
        ax2.set_title('TOP 10 Most Suspicious Events (Combined View)', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Number of Occurrences')
        
        # Добавляем значения на столбцы
        for i, v in enumerate(top_combined.values):
            ax2.text(v + 0.5, i, str(v), va='center')
    
    plt.tight_layout()
    plt.show()

def print_suspicious_summary(suspicious_df):
    """
    Вывод сводки по подозрительным событиям
    """
    print("\n" + "="*80)
    print("SUMMARY OF SUSPICIOUS EVENTS")
    print("="*80)
    
    if suspicious_df.empty:
        print("No suspicious events found.")
        return
    
    print(f"Total suspicious events: {len(suspicious_df)}")
    print(f"Unique event types: {suspicious_df['event_id'].nunique()}")
    print(f"Affected hosts: {suspicious_df['computer'].nunique()}")
    print(f"Affected users: {suspicious_df['user'].nunique()}")
    
    print("\n" + "-"*80)
    print("TOP 10 MOST SUSPICIOUS EVENTS:")
    print("-"*80)
    
    top_suspicious = suspicious_df.groupby(['event_id', 'event_name']).size().reset_index(name='count')
    top_suspicious = top_suspicious.sort_values('count', ascending=False).head(10)
    
    for idx, row in top_suspicious.iterrows():
        print(f"{int(row['event_id'])}: {row['event_name']} - {row['count']} occurrences")
    
    # Показываем примеры высокорисковых событий
    high_risk = suspicious_df[suspicious_df['suspicious_score'] >= 3]
    if not high_risk.empty:
        print("\n" + "-"*80)
        print("HIGH-RISK EVENTS DETECTED:")
        print("-"*80)
        for idx, row in high_risk.head(5).iterrows():
            print(f"[{row['timestamp']}] {row['computer']} - {row['event_name']}")
            print(f"  User: {row['user']}")
            print(f"  Reasons: {row['reasons']}")
            print()

def main():
    """
    Основная функция
    """
    # Загрузка данных
    print("Loading data...")
    df = load_and_prepare_data('botsv1.json')
    
    # Базовая статистика
    print("\n" + "="*80)
    print("BASIC STATISTICS")
    print("="*80)
    print(f"Unique Event Codes: {df['EventCode'].nunique()}")
    print(f"Unique Computers: {df['ComputerName'].nunique()}")
    print(f"Unique Users: {df['user'].nunique()}")
    
    # Анализ подозрительных событий
    print("\nAnalyzing suspicious events...")
    suspicious_df = analyze_suspicious_windows_events(df)
    
    # Вывод сводки
    print_suspicious_summary(suspicious_df)
    
    # Создание визуализаций
    print("\nCreating visualizations...")
    create_visualizations(suspicious_df, df)
    
    # Сохранение результатов (опционально)
    if not suspicious_df.empty:
        suspicious_df.to_csv('suspicious_events.csv', index=False)
        print("\nSuspicious events saved to 'suspicious_events.csv'")
    
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()
