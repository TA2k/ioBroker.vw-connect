.class public final Lc3/x;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lc3/v;

.field public final synthetic h:Lc3/v;

.field public final synthetic i:I

.field public final synthetic j:La3/g;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lc3/v;Lc3/v;Ljava/lang/Object;ILa3/g;I)V
    .locals 0

    .line 1
    iput p6, p0, Lc3/x;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lc3/x;->g:Lc3/v;

    .line 4
    .line 5
    iput-object p2, p0, Lc3/x;->h:Lc3/v;

    .line 6
    .line 7
    iput-object p3, p0, Lc3/x;->k:Ljava/lang/Object;

    .line 8
    .line 9
    iput p4, p0, Lc3/x;->i:I

    .line 10
    .line 11
    iput-object p5, p0, Lc3/x;->j:La3/g;

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lc3/x;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt3/e;

    .line 7
    .line 8
    iget-object v0, p0, Lc3/x;->h:Lc3/v;

    .line 9
    .line 10
    invoke-static {v0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Lw3/t;

    .line 15
    .line 16
    invoke-virtual {v1}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lc3/l;

    .line 21
    .line 22
    iget-object v1, v1, Lc3/l;->h:Lc3/v;

    .line 23
    .line 24
    iget-object v2, p0, Lc3/x;->g:Lc3/v;

    .line 25
    .line 26
    if-eq v2, v1, :cond_0

    .line 27
    .line 28
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    iget-object v1, p0, Lc3/x;->k:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v1, Ld3/c;

    .line 34
    .line 35
    iget v2, p0, Lc3/x;->i:I

    .line 36
    .line 37
    iget-object p0, p0, Lc3/x;->j:La3/g;

    .line 38
    .line 39
    invoke-static {v2, p0, v0, v1}, Lc3/f;->A(ILa3/g;Lc3/v;Ld3/c;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    if-nez p0, :cond_2

    .line 48
    .line 49
    invoke-interface {p1}, Lt3/e;->a()Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-nez p0, :cond_1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    const/4 p0, 0x0

    .line 57
    goto :goto_1

    .line 58
    :cond_2
    :goto_0
    move-object p0, v0

    .line 59
    :goto_1
    return-object p0

    .line 60
    :pswitch_0
    check-cast p1, Lt3/e;

    .line 61
    .line 62
    iget-object v0, p0, Lc3/x;->h:Lc3/v;

    .line 63
    .line 64
    invoke-static {v0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    check-cast v1, Lw3/t;

    .line 69
    .line 70
    invoke-virtual {v1}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    check-cast v1, Lc3/l;

    .line 75
    .line 76
    iget-object v1, v1, Lc3/l;->h:Lc3/v;

    .line 77
    .line 78
    iget-object v2, p0, Lc3/x;->g:Lc3/v;

    .line 79
    .line 80
    if-eq v2, v1, :cond_3

    .line 81
    .line 82
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_3
    iget-object v1, p0, Lc3/x;->k:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v1, Lc3/v;

    .line 88
    .line 89
    iget v2, p0, Lc3/x;->i:I

    .line 90
    .line 91
    iget-object p0, p0, Lc3/x;->j:La3/g;

    .line 92
    .line 93
    invoke-static {v0, v1, v2, p0}, Lc3/f;->B(Lc3/v;Lc3/v;ILa3/g;)Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    if-nez p0, :cond_5

    .line 102
    .line 103
    invoke-interface {p1}, Lt3/e;->a()Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-nez p0, :cond_4

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    const/4 p0, 0x0

    .line 111
    goto :goto_3

    .line 112
    :cond_5
    :goto_2
    move-object p0, v0

    .line 113
    :goto_3
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
