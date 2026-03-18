.class public final Lsa0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsa0/k;


# direct methods
.method public synthetic constructor <init>(Lsa0/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsa0/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/h;->e:Lsa0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p2, p0, Lsa0/h;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    check-cast p1, Lne0/e;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object p1, v0

    .line 17
    :goto_0
    if-eqz p1, :cond_1

    .line 18
    .line 19
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v0, p1

    .line 22
    check-cast v0, Lra0/a;

    .line 23
    .line 24
    :cond_1
    iget-object p0, p0, Lsa0/h;->e:Lsa0/k;

    .line 25
    .line 26
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Lsa0/j;

    .line 31
    .line 32
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    sget-object v1, Lra0/c;->f:Lra0/c;

    .line 37
    .line 38
    invoke-virtual {p2, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    sget-object v1, Lra0/c;->e:Lra0/c;

    .line 42
    .line 43
    invoke-virtual {p2, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    sget-object v1, Lra0/c;->d:Lra0/c;

    .line 47
    .line 48
    invoke-virtual {p2, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    sget-object v0, Lra0/c;->i:Lra0/c;

    .line 54
    .line 55
    invoke-virtual {p2, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    sget-object v0, Lra0/c;->j:Lra0/c;

    .line 59
    .line 60
    invoke-virtual {p2, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    :cond_2
    invoke-static {p2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    const/4 v0, 0x0

    .line 68
    const/4 v1, 0x2

    .line 69
    invoke-static {p1, p2, v0, v1}, Lsa0/j;->a(Lsa0/j;Lnx0/c;ZI)Lsa0/j;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    iget-object p0, p0, Lsa0/h;->e:Lsa0/k;

    .line 86
    .line 87
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    check-cast p2, Lsa0/j;

    .line 92
    .line 93
    const/4 v0, 0x0

    .line 94
    const/4 v1, 0x1

    .line 95
    invoke-static {p2, v0, p1, v1}, Lsa0/j;->a(Lsa0/j;Lnx0/c;ZI)Lsa0/j;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 100
    .line 101
    .line 102
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
