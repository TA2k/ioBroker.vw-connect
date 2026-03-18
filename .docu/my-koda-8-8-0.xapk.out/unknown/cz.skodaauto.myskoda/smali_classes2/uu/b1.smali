.class public final Luu/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Luu/b1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu/b1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Luu/b1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Luu/b1;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Luu/b1;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Luu/b1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luu/b1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    new-instance v1, Lxk0/c0;

    .line 11
    .line 12
    iget-object v2, p0, Luu/b1;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lh2/r8;

    .line 15
    .line 16
    const/4 v3, 0x5

    .line 17
    const/4 v4, 0x0

    .line 18
    invoke-direct {v1, v2, v4, v3}, Lxk0/c0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x3

    .line 22
    invoke-static {v0, v4, v4, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Luu/b1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Lay0/k;

    .line 28
    .line 29
    iget-object p0, p0, Luu/b1;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Ly20/g;

    .line 32
    .line 33
    iget-object p0, p0, Ly20/g;->a:Lss0/d0;

    .line 34
    .line 35
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object v0, p0, Luu/b1;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Luu/e1;

    .line 44
    .line 45
    iget-object v1, v0, Luu/e1;->b:Ll2/j1;

    .line 46
    .line 47
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    move-object v5, v1

    .line 52
    check-cast v5, Ljava/lang/String;

    .line 53
    .line 54
    iget-object v1, v0, Luu/e1;->c:Ll2/j1;

    .line 55
    .line 56
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    move-object v4, v1

    .line 61
    check-cast v4, Luu/g;

    .line 62
    .line 63
    iget-object v0, v0, Luu/e1;->d:Ll2/j1;

    .line 64
    .line 65
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    move-object v8, v0

    .line 70
    check-cast v8, Lk1/z0;

    .line 71
    .line 72
    new-instance v2, Luu/x0;

    .line 73
    .line 74
    iget-object v0, p0, Luu/b1;->f:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v3, v0

    .line 77
    check-cast v3, Lqp/g;

    .line 78
    .line 79
    iget-object v0, p0, Luu/b1;->g:Ljava/lang/Object;

    .line 80
    .line 81
    move-object v6, v0

    .line 82
    check-cast v6, Lt4/c;

    .line 83
    .line 84
    iget-object p0, p0, Luu/b1;->h:Ljava/lang/Object;

    .line 85
    .line 86
    move-object v7, p0

    .line 87
    check-cast v7, Lt4/m;

    .line 88
    .line 89
    invoke-direct/range {v2 .. v8}, Luu/x0;-><init>(Lqp/g;Luu/g;Ljava/lang/String;Lt4/c;Lt4/m;Lk1/z0;)V

    .line 90
    .line 91
    .line 92
    return-object v2

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
