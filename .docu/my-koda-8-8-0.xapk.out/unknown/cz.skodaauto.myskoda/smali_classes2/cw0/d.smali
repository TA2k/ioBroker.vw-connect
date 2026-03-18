.class public final synthetic Lcw0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcw0/e;


# direct methods
.method public synthetic constructor <init>(Lcw0/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcw0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcw0/d;->e:Lcw0/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lcw0/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcw0/d;->e:Lcw0/e;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance v0, Lvy0/z1;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lk4/r;

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    sget-object v3, Lvy0/y;->d:Lvy0/y;

    .line 18
    .line 19
    invoke-direct {v1, v3, v2}, Lk4/r;-><init>(Lpx0/f;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v1}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iget-object v1, p0, Lcw0/e;->e:Llx0/q;

    .line 27
    .line 28
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lvy0/x;

    .line 33
    .line 34
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    new-instance v1, Lvy0/a0;

    .line 39
    .line 40
    iget-object p0, p0, Lcw0/e;->d:Ljava/lang/String;

    .line 41
    .line 42
    const-string v2, "-context"

    .line 43
    .line 44
    invoke-virtual {p0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-direct {v1, p0}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_0
    invoke-interface {p0}, Lcw0/c;->p()Ldw0/a;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    sget-object p0, Lvy0/p0;->a:Lcz0/e;

    .line 64
    .line 65
    sget-object p0, Lcz0/d;->e:Lcz0/d;

    .line 66
    .line 67
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
