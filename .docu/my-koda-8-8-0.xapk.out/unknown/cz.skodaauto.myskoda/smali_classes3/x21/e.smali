.class public final Lx21/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j0;


# instance fields
.field public final synthetic a:Lay0/a;

.field public final synthetic b:Ll2/b1;

.field public final synthetic c:Ll2/b1;

.field public final synthetic d:Lvy0/b0;


# direct methods
.method public constructor <init>(Lay0/a;Ll2/b1;Ll2/b1;Lvy0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx21/e;->a:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lx21/e;->b:Ll2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Lx21/e;->c:Ll2/b1;

    .line 9
    .line 10
    iput-object p4, p0, Lx21/e;->d:Lvy0/b0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final dispose()V
    .locals 5

    .line 1
    iget-object v0, p0, Lx21/e;->b:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    iget-object v1, p0, Lx21/e;->c:Ll2/b1;

    .line 16
    .line 17
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Li1/b;

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    new-instance v2, Lx21/d;

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct {v2, v1, v4, v3}, Lx21/d;-><init>(Li1/b;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    iget-object v3, p0, Lx21/e;->d:Lvy0/b0;

    .line 34
    .line 35
    invoke-static {v3, v4, v4, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    :cond_0
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    iget-object p0, p0, Lx21/e;->a:Lay0/a;

    .line 51
    .line 52
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    :cond_1
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_2
    return-void
.end method
