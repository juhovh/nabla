#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QtGui/QMainWindow>

namespace Ui
{
    class LoginWindowClass;
}

class LoginWindow : public QMainWindow
{
    Q_OBJECT

public:
    LoginWindow(QWidget *parent = 0);
    ~LoginWindow();

private:
    Ui::LoginWindowClass *ui;
};

#endif // LOGINWINDOW_H
