.class public final synthetic Lz31/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz31/e;


# direct methods
.method public synthetic constructor <init>(Lz31/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lz31/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz31/d;->e:Lz31/e;

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
    .locals 11

    .line 1
    iget v0, p0, Lz31/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/b0;

    .line 7
    .line 8
    iget-object v0, p0, Lz31/d;->e:Lz31/e;

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
    check-cast v2, Lz31/g;

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
    move-result-object v9

    .line 26
    const/16 v10, 0xf

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
    const-string v8, ""

    .line 34
    .line 35
    invoke-static/range {v2 .. v10}, Lz31/g;->a(Lz31/g;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;I)Lz31/g;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {v1, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-eqz p0, :cond_0

    .line 44
    .line 45
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    new-instance p1, Lyj0/c;

    .line 50
    .line 51
    const/4 v1, 0x3

    .line 52
    const/4 v2, 0x0

    .line 53
    invoke-direct {p1, v0, v2, v1}, Lyj0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    const/4 v0, 0x3

    .line 57
    invoke-static {p0, v2, v2, p1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 58
    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 64
    .line 65
    iget-object p0, p0, Lz31/d;->e:Lz31/e;

    .line 66
    .line 67
    iget-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 68
    .line 69
    :cond_1
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    move-object v1, v0

    .line 74
    check-cast v1, Lz31/g;

    .line 75
    .line 76
    iget-object v7, p0, Lz31/e;->f:Ljava/lang/String;

    .line 77
    .line 78
    const/4 v8, 0x0

    .line 79
    const/4 v9, 0x7

    .line 80
    const/4 v2, 0x0

    .line 81
    const/4 v3, 0x0

    .line 82
    const/4 v4, 0x0

    .line 83
    const/4 v5, 0x1

    .line 84
    const/4 v6, 0x0

    .line 85
    invoke-static/range {v1 .. v9}, Lz31/g;->a(Lz31/g;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;I)Lz31/g;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_1

    .line 94
    .line 95
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    return-object p0

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
