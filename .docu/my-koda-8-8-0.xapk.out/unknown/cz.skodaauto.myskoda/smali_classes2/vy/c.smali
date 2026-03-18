.class public final Lvy/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy/h;


# direct methods
.method public synthetic constructor <init>(Lvy/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvy/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvy/c;->e:Lvy/h;

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
    .locals 10

    .line 1
    iget v0, p0, Lvy/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of v0, p1, Lne0/c;

    .line 9
    .line 10
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object p0, p0, Lvy/c;->e:Lvy/h;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lvy/h;->q:Ljn0/c;

    .line 17
    .line 18
    check-cast p1, Lne0/c;

    .line 19
    .line 20
    invoke-virtual {p0, p1, p2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 25
    .line 26
    if-ne p0, p1, :cond_1

    .line 27
    .line 28
    move-object v1, p0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    instance-of p1, p1, Lne0/e;

    .line 31
    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lvy/d;

    .line 39
    .line 40
    iget-object p2, p0, Lvy/h;->k:Lij0/a;

    .line 41
    .line 42
    const/4 v0, 0x1

    .line 43
    invoke-static {p1, p2, v0}, Llp/oc;->a(Lvy/d;Lij0/a;Z)Lvy/d;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    :goto_0
    return-object v1

    .line 51
    :cond_2
    new-instance p0, La8/r0;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :pswitch_0
    check-cast p1, Lss0/j0;

    .line 58
    .line 59
    new-instance p1, Lvy/d;

    .line 60
    .line 61
    const/4 p2, 0x0

    .line 62
    const/16 v0, 0x3ff

    .line 63
    .line 64
    invoke-direct {p1, p2, p2, p2, v0}, Lvy/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lvy/c;->e:Lvy/h;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 78
    .line 79
    .line 80
    move-result v7

    .line 81
    iget-object p0, p0, Lvy/c;->e:Lvy/h;

    .line 82
    .line 83
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    move-object v0, p1

    .line 88
    check-cast v0, Lvy/d;

    .line 89
    .line 90
    const/4 v8, 0x0

    .line 91
    const/16 v9, 0x2ff

    .line 92
    .line 93
    const/4 v1, 0x0

    .line 94
    const/4 v2, 0x0

    .line 95
    const/4 v3, 0x0

    .line 96
    const/4 v4, 0x0

    .line 97
    const/4 v5, 0x0

    .line 98
    const/4 v6, 0x0

    .line 99
    invoke-static/range {v0 .. v9}, Lvy/d;->a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 104
    .line 105
    .line 106
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
