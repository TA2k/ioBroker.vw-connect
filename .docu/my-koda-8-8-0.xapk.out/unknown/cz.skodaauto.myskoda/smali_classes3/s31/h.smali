.class public final synthetic Ls31/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls31/i;


# direct methods
.method public synthetic constructor <init>(Ls31/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Ls31/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls31/h;->e:Ls31/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Ls31/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/b0;

    .line 7
    .line 8
    iget-object v0, p0, Ls31/h;->e:Ls31/i;

    .line 9
    .line 10
    iget-object v1, v0, Lq41/b;->d:Lyy0/c2;

    .line 11
    .line 12
    :cond_0
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    move-object v2, p0

    .line 17
    check-cast v2, Ls31/k;

    .line 18
    .line 19
    const p1, 0x7f0800c7

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v12

    .line 26
    const/16 v13, 0x7f

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v7, 0x0

    .line 33
    const/4 v8, 0x0

    .line 34
    const/4 v9, 0x0

    .line 35
    const/4 v10, 0x0

    .line 36
    const-string v11, ""

    .line 37
    .line 38
    invoke-static/range {v2 .. v13}, Ls31/k;->a(Ls31/k;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZZLjava/lang/String;Ljava/lang/Integer;I)Ls31/k;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {v1, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    new-instance p1, Lrp0/a;

    .line 53
    .line 54
    const/4 v1, 0x5

    .line 55
    const/4 v2, 0x0

    .line 56
    invoke-direct {p1, v0, v2, v1}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    const/4 v0, 0x3

    .line 60
    invoke-static {p0, v2, v2, p1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 61
    .line 62
    .line 63
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 67
    .line 68
    iget-object p0, p0, Ls31/h;->e:Ls31/i;

    .line 69
    .line 70
    iget-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 71
    .line 72
    :cond_1
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    move-object v1, v0

    .line 77
    check-cast v1, Ls31/k;

    .line 78
    .line 79
    iget-object v10, p0, Ls31/i;->g:Ljava/lang/String;

    .line 80
    .line 81
    const/4 v11, 0x0

    .line 82
    const/16 v12, 0x3f

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    const/4 v3, 0x0

    .line 86
    const/4 v4, 0x0

    .line 87
    const/4 v5, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    const/4 v8, 0x1

    .line 91
    const/4 v9, 0x0

    .line 92
    invoke-static/range {v1 .. v12}, Ls31/k;->a(Ls31/k;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZZLjava/lang/String;Ljava/lang/Integer;I)Ls31/k;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-eqz v0, :cond_1

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
