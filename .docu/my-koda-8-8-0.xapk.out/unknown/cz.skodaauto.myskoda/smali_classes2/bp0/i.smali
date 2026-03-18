.class public final Lbp0/i;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# instance fields
.field public final d:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 5
    .line 6
    new-instance v1, Lbp0/h;

    .line 7
    .line 8
    const/4 v2, 0x6

    .line 9
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iput-object v0, p0, Lbp0/i;->d:Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "intent"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p1, Lay/b;

    .line 12
    .line 13
    const/16 p2, 0xc

    .line 14
    .line 15
    invoke-direct {p1, p2}, Lay/b;-><init>(I)V

    .line 16
    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    invoke-static {p2, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lbp0/i;->d:Ljava/lang/Object;

    .line 23
    .line 24
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lxo0/a;

    .line 29
    .line 30
    iget-object p0, p0, Lxo0/a;->d:Lyy0/q1;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    return-void
.end method
