import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns
import pickle

class MachineLearning():
    def __init__(self):
        print("Loading dataset ...")
        
        # Đọc file CSV
        self.flow_dataset = pd.read_csv('dataset.csv')

        # Loại bỏ khoảng trắng ở tên cột
        self.flow_dataset.columns = self.flow_dataset.columns.str.strip()

        # Xác định các cột cần thay đổi
        columns_to_convert = ['Total Fwd Packets', 'Total Backward Packets', 'Total Length of Bwd Packets']

        # Chuyển đổi cột sang kiểu số và thay thế giá trị NaN
        for col in columns_to_convert:
            # Chuyển đổi cột sang kiểu số với cách xử lý lỗi
            self.flow_dataset[col] = pd.to_numeric(self.flow_dataset[col], errors='coerce')

            # Đặt giá trị NaN thành 0 và chuyển sang int
            self.flow_dataset[col] = self.flow_dataset[col].fillna(0).astype(int)

        # Xử lý NaN và giá trị vô hạn
        self.flow_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.flow_dataset.dropna(inplace=True)
        
        # Tách dữ liệu thành features và labels
        self.X_flow = self.flow_dataset.iloc[:, :-1]  # Tất cả các cột trừ cột cuối
        self.y_flow = self.flow_dataset.iloc[:, -1]   # Cột cuối là nhãn

        # Tách dữ liệu thành tập huấn luyện và tập kiểm tra
        self.X_flow_train, self.X_flow_test, self.y_flow_train, self.y_flow_test = train_test_split(
            self.X_flow, self.y_flow, test_size=0.2, random_state=42
        )

    def flow_training(self):
        print("Flow Training ...")
        
        # Khởi tạo mô hình Random Forest
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Huấn luyện mô hình trên dữ liệu huấn luyện
        self.classifier.fit(self.X_flow_train, self.y_flow_train)
        
        # Dự đoán trên dữ liệu kiểm tra
        y_pred = self.classifier.predict(self.X_flow_test)
        
        # Tính toán độ chính xác và các chỉ số khác
        accuracy = accuracy_score(self.y_flow_test, y_pred)
        precision = precision_score(self.y_flow_test, y_pred, average='macro')
        recall = recall_score(self.y_flow_test, y_pred, average='macro')
        f1 = f1_score(self.y_flow_test, y_pred, average='macro')
        cm = confusion_matrix(self.y_flow_test, y_pred)
        
        # In các chỉ số
        print(f"Accuracy: {accuracy}")
        print(f"Precision: {precision}")
        print(f"Recall: {recall}")
        print(f"F1-score: {f1}")
        print("Confusion Matrix:")
        print(cm)

        # Lưu mô hình
        try:
            with open('model.pkl', 'wb') as file:
                pickle.dump(self.classifier, file)  # Lưu model classifier
            print("Model has been saved to 'model.pkl'.")
        except Exception as e:
            print(f"Error saving the model: {e}")

        # Vẽ biểu đồ Confusion Matrix với nhãn
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Benign', 'DoS', 'DDoS', 'Port scan'], 
                    yticklabels=['Benign', 'DoS', 'DDoS', 'Port scan'])
        
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted Label')
        plt.ylabel('True Label')
        plt.show()

        

def main():
    # Khởi tạo lớp MachineLearning
    ml = MachineLearning()
    
    # Huấn luyện mô hình
    ml.flow_training() 

if __name__ == "__main__":
    main()
