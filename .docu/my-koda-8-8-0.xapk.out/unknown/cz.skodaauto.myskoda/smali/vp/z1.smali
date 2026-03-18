.class public final Lvp/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/media3/ui/AspectRatioFrameLayout;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/z1;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/z1;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/j2;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/z1;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Lvp/z1;->e:Z

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/z1;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget v0, p0, Lvp/z1;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    packed-switch v0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    iput-boolean v1, p0, Lvp/z1;->e:Z

    .line 8
    .line 9
    iget-object p0, p0, Lvp/z1;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroidx/media3/ui/AspectRatioFrameLayout;

    .line 12
    .line 13
    sget v0, Landroidx/media3/ui/AspectRatioFrameLayout;->g:I

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    iget-object v0, p0, Lvp/z1;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lvp/j2;

    .line 22
    .line 23
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, Lvp/g1;

    .line 26
    .line 27
    invoke-virtual {v2}, Lvp/g1;->a()Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    iget-object v4, v2, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v4, :cond_0

    .line 35
    .line 36
    iget-object v4, v2, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_0

    .line 43
    .line 44
    move v4, v5

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move v4, v1

    .line 47
    :goto_0
    iget-boolean p0, p0, Lvp/z1;->e:Z

    .line 48
    .line 49
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    iput-object v6, v2, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 54
    .line 55
    if-ne v4, p0, :cond_1

    .line 56
    .line 57
    iget-object v4, v2, Lvp/g1;->i:Lvp/p0;

    .line 58
    .line 59
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    iget-object v4, v4, Lvp/p0;->r:Lvp/n0;

    .line 63
    .line 64
    const-string v6, "Default data collection state already set to"

    .line 65
    .line 66
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 67
    .line 68
    .line 69
    move-result-object v7

    .line 70
    invoke-virtual {v4, v7, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    :cond_1
    invoke-virtual {v2}, Lvp/g1;->a()Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eq v4, v3, :cond_3

    .line 78
    .line 79
    invoke-virtual {v2}, Lvp/g1;->a()Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    iget-object v6, v2, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 84
    .line 85
    if-eqz v6, :cond_2

    .line 86
    .line 87
    iget-object v6, v2, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 88
    .line 89
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 90
    .line 91
    .line 92
    move-result v6

    .line 93
    if-eqz v6, :cond_2

    .line 94
    .line 95
    move v1, v5

    .line 96
    :cond_2
    if-eq v4, v1, :cond_4

    .line 97
    .line 98
    :cond_3
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 99
    .line 100
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, v1, Lvp/p0;->o:Lvp/n0;

    .line 104
    .line 105
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    const-string v3, "Default data collection is different than actual status"

    .line 114
    .line 115
    invoke-virtual {v1, p0, v2, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    :cond_4
    invoke-virtual {v0}, Lvp/j2;->s0()V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
