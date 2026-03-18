.class public final Ldv/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/m;
.implements Lgs/e;
.implements Loa/a;
.implements Lc1/c0;
.implements Lk4/b0;
.implements Lgs/f;
.implements Lpx0/f;
.implements Llp/jg;
.implements Lkx0/a;
.implements Lus/b;
.implements Lvp/u;
.implements Lmy0/b;
.implements Lxm/b;


# static fields
.field public static final synthetic e:Ldv/a;

.field public static final synthetic f:Ldv/a;

.field public static final synthetic g:Ldv/a;

.field public static final synthetic h:Ldv/a;

.field public static final synthetic i:Ldv/a;

.field public static final synthetic j:Ldv/a;

.field public static final synthetic k:Ldv/a;

.field public static final synthetic l:Ldv/a;

.field public static final synthetic m:Ldv/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ldv/a;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ldv/a;->e:Ldv/a;

    .line 9
    .line 10
    new-instance v0, Ldv/a;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Ldv/a;->f:Ldv/a;

    .line 18
    .line 19
    new-instance v0, Ldv/a;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Ldv/a;->g:Ldv/a;

    .line 27
    .line 28
    new-instance v0, Ldv/a;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Ldv/a;->h:Ldv/a;

    .line 36
    .line 37
    new-instance v0, Ldv/a;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Ldv/a;->i:Ldv/a;

    .line 45
    .line 46
    new-instance v0, Ldv/a;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Ldv/a;->j:Ldv/a;

    .line 54
    .line 55
    new-instance v0, Ldv/a;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Ldv/a;->k:Ldv/a;

    .line 63
    .line 64
    new-instance v0, Ldv/a;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Ldv/a;->l:Ldv/a;

    .line 72
    .line 73
    new-instance v0, Ldv/a;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Ldv/a;->m:Ldv/a;

    .line 81
    .line 82
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ldv/a;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x23

    if-lt p0, v0, :cond_0

    .line 5
    new-instance p0, La8/n;

    :cond_0
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ldv/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/w;)V
    .locals 0

    const/16 p1, 0xd

    iput p1, p0, Ldv/a;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public C()F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public K(F)J
    .locals 0

    .line 1
    const-wide/16 p0, 0x0

    .line 2
    .line 3
    return-wide p0
.end method

.method public M(FF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public O(JF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public S(JFF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public a(Lcom/google/firebase/components/ComponentRegistrar;)Ljava/util/List;
    .locals 9

    .line 1
    new-instance p0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lcom/google/firebase/components/ComponentRegistrar;->getComponents()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lgs/b;

    .line 25
    .line 26
    iget-object v2, v0, Lgs/b;->a:Ljava/lang/String;

    .line 27
    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    new-instance v7, La0/h;

    .line 31
    .line 32
    const/16 v1, 0x13

    .line 33
    .line 34
    invoke-direct {v7, v1, v2, v0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lgs/b;

    .line 38
    .line 39
    iget-object v3, v0, Lgs/b;->b:Ljava/util/Set;

    .line 40
    .line 41
    iget-object v4, v0, Lgs/b;->c:Ljava/util/Set;

    .line 42
    .line 43
    iget v5, v0, Lgs/b;->d:I

    .line 44
    .line 45
    iget v6, v0, Lgs/b;->e:I

    .line 46
    .line 47
    iget-object v8, v0, Lgs/b;->g:Ljava/util/Set;

    .line 48
    .line 49
    invoke-direct/range {v1 .. v8}, Lgs/b;-><init>(Ljava/lang/String;Ljava/util/Set;Ljava/util/Set;IILgs/e;Ljava/util/Set;)V

    .line 50
    .line 51
    .line 52
    move-object v0, v1

    .line 53
    :cond_0
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    return-object p0
.end method

.method public b(F)Z
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string p1, "not implemented"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public c()Lhn/a;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "not implemented"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public d(F)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lev/b;

    .line 2
    .line 3
    const-class v0, Ldv/a;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lin/z1;->f(Ljava/lang/Class;)Lgt/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Lev/b;-><init>(Lgt/b;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public f()F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Llp/yd;

    .line 2
    .line 3
    iget-object p0, p1, Llp/yd;->e:Llp/y1;

    .line 4
    .line 5
    iget-object v0, p1, Llp/yd;->i:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0}, Lpv/b;->b(Llp/y1;)Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance v1, Lov/a;

    .line 12
    .line 13
    iget-object v2, p1, Llp/yd;->g:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v2}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    const-string v2, ""

    .line 22
    .line 23
    :cond_0
    invoke-static {p0}, Lpv/b;->a(Ljava/util/List;)Landroid/graphics/Rect;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-static {v0}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    const-string v0, "und"

    .line 34
    .line 35
    :cond_1
    iget-object p1, p1, Llp/yd;->e:Llp/y1;

    .line 36
    .line 37
    iget p1, p1, Llp/y1;->h:F

    .line 38
    .line 39
    sget-object p1, Llp/o;->e:Llp/m;

    .line 40
    .line 41
    sget-object p1, Llp/u;->h:Llp/u;

    .line 42
    .line 43
    invoke-direct {v1, v2, v3, p0, v0}, Lh/w;-><init>(Ljava/lang/String;Landroid/graphics/Rect;Ljava/util/List;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-object v1
.end method

.method public get()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getInstance()Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Ldv/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/q7;->e:Lcom/google/android/gms/internal/measurement/q7;

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/q7;->d:Lgr/p;

    .line 11
    .line 12
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lcom/google/android/gms/internal/measurement/r7;

    .line 15
    .line 16
    sget-object p0, Lcom/google/android/gms/internal/measurement/s7;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Ljava/lang/Boolean;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 29
    .line 30
    sget-object p0, Lcom/google/android/gms/internal/measurement/k7;->e:Lcom/google/android/gms/internal/measurement/k7;

    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k7;->d:Lgr/p;

    .line 33
    .line 34
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lcom/google/android/gms/internal/measurement/l7;

    .line 37
    .line 38
    sget-object p0, Lcom/google/android/gms/internal/measurement/m7;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 39
    .line 40
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ljava/lang/Long;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    long-to-int p0, v0

    .line 51
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 57
    .line 58
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 59
    .line 60
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 61
    .line 62
    .line 63
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->X:Lcom/google/android/gms/internal/measurement/n4;

    .line 64
    .line 65
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Ljava/lang/Long;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 72
    .line 73
    .line 74
    move-result-wide v0

    .line 75
    long-to-int p0, v0

    .line 76
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 82
    .line 83
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 84
    .line 85
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 86
    .line 87
    .line 88
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->x:Lcom/google/android/gms/internal/measurement/n4;

    .line 89
    .line 90
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    check-cast p0, Ljava/lang/Long;

    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v0

    .line 100
    long-to-int p0, v0

    .line 101
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 107
    .line 108
    sget-object p0, Lcom/google/android/gms/internal/measurement/r8;->e:Lcom/google/android/gms/internal/measurement/r8;

    .line 109
    .line 110
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/r8;->a()Lcom/google/android/gms/internal/measurement/s8;

    .line 111
    .line 112
    .line 113
    sget-object p0, Lcom/google/android/gms/internal/measurement/t8;->f:Lcom/google/android/gms/internal/measurement/n4;

    .line 114
    .line 115
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    check-cast p0, Ljava/lang/String;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 123
    .line 124
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 125
    .line 126
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 127
    .line 128
    .line 129
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->V:Lcom/google/android/gms/internal/measurement/n4;

    .line 130
    .line 131
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    check-cast p0, Ljava/lang/Long;

    .line 136
    .line 137
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    return-object p0

    .line 141
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 142
    .line 143
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 144
    .line 145
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 146
    .line 147
    .line 148
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->O:Lcom/google/android/gms/internal/measurement/n4;

    .line 149
    .line 150
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    check-cast p0, Ljava/lang/Long;

    .line 155
    .line 156
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 157
    .line 158
    .line 159
    move-result-wide v0

    .line 160
    long-to-int p0, v0

    .line 161
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 167
    .line 168
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 169
    .line 170
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 171
    .line 172
    .line 173
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->q0:Lcom/google/android/gms/internal/measurement/n4;

    .line 174
    .line 175
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    check-cast p0, Ljava/lang/Long;

    .line 180
    .line 181
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 182
    .line 183
    .line 184
    move-result-wide v0

    .line 185
    long-to-int p0, v0

    .line 186
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    return-object p0

    .line 191
    :pswitch_7
    sget-object p0, Lcom/google/android/gms/internal/measurement/t7;->e:Lcom/google/android/gms/internal/measurement/t7;

    .line 192
    .line 193
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/t7;->d:Lgr/p;

    .line 194
    .line 195
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast p0, Lcom/google/android/gms/internal/measurement/u7;

    .line 198
    .line 199
    sget-object p0, Lcom/google/android/gms/internal/measurement/v7;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 200
    .line 201
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    check-cast p0, Ljava/lang/Boolean;

    .line 206
    .line 207
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    new-instance v0, Ljava/lang/Boolean;

    .line 212
    .line 213
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 214
    .line 215
    .line 216
    return-object v0

    .line 217
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public isEmpty()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public j()F
    .locals 0

    .line 1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    return p0
.end method

.method public k(Lko/p;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lcq/n;

    .line 2
    .line 3
    iget-object p0, p1, Lcq/n;->e:Lbq/b;

    .line 4
    .line 5
    return-object p0
.end method

.method public l(Landroidx/sqlite/db/SupportSQLiteDatabase;)V
    .locals 6

    .line 1
    const-string p0, "db"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "UPDATE workspec SET period_count = 1 WHERE last_enqueue_time <> 0 AND interval_duration <> 0"

    .line 7
    .line 8
    invoke-interface {p1, p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v3, Landroid/content/ContentValues;

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    invoke-direct {v3, p0}, Landroid/content/ContentValues;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "last_enqueue_time"

    .line 26
    .line 27
    invoke-virtual {v3, v0, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    new-array v5, p0, [Ljava/lang/Object;

    .line 32
    .line 33
    const-string v1, "WorkSpec"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    const-string v4, "last_enqueue_time = 0 AND interval_duration <> 0 "

    .line 37
    .line 38
    move-object v0, p1

    .line 39
    invoke-interface/range {v0 .. v5}, Landroidx/sqlite/db/SupportSQLiteDatabase;->update(Ljava/lang/String;ILandroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public m(Lwe0/b;Lorg/json/JSONObject;)Lus/a;
    .locals 13

    .line 1
    const-string p0, "settings_version"

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-virtual {p2, p0, p1}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 5
    .line 6
    .line 7
    const-string p0, "cache_duration"

    .line 8
    .line 9
    const/16 v0, 0xe10

    .line 10
    .line 11
    invoke-virtual {p2, p0, v0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const-string v0, "on_demand_upload_rate_per_minute"

    .line 16
    .line 17
    const-wide/high16 v1, 0x4024000000000000L    # 10.0

    .line 18
    .line 19
    invoke-virtual {p2, v0, v1, v2}, Lorg/json/JSONObject;->optDouble(Ljava/lang/String;D)D

    .line 20
    .line 21
    .line 22
    move-result-wide v8

    .line 23
    const-string v0, "on_demand_backoff_base"

    .line 24
    .line 25
    const-wide v1, 0x3ff3333333333333L    # 1.2

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    invoke-virtual {p2, v0, v1, v2}, Lorg/json/JSONObject;->optDouble(Ljava/lang/String;D)D

    .line 31
    .line 32
    .line 33
    move-result-wide v10

    .line 34
    const-string v0, "on_demand_backoff_step_duration_seconds"

    .line 35
    .line 36
    const/16 v1, 0x3c

    .line 37
    .line 38
    invoke-virtual {p2, v0, v1}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 39
    .line 40
    .line 41
    move-result v12

    .line 42
    const-string v0, "session"

    .line 43
    .line 44
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    const/16 v2, 0x8

    .line 49
    .line 50
    const-string v3, "max_custom_exception_events"

    .line 51
    .line 52
    if-eqz v1, :cond_0

    .line 53
    .line 54
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-virtual {v0, v3, v2}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    new-instance v1, Lc1/l2;

    .line 63
    .line 64
    const/4 v2, 0x7

    .line 65
    invoke-direct {v1, v0, v2}, Lc1/l2;-><init>(II)V

    .line 66
    .line 67
    .line 68
    :goto_0
    move-object v6, v1

    .line 69
    goto :goto_1

    .line 70
    :cond_0
    new-instance v0, Lorg/json/JSONObject;

    .line 71
    .line 72
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, v3, v2}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    new-instance v1, Lc1/l2;

    .line 80
    .line 81
    const/4 v2, 0x7

    .line 82
    invoke-direct {v1, v0, v2}, Lc1/l2;-><init>(II)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_1
    const-string v0, "features"

    .line 87
    .line 88
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    const-string v1, "collect_reports"

    .line 93
    .line 94
    const/4 v2, 0x1

    .line 95
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    const-string v2, "collect_anrs"

    .line 100
    .line 101
    invoke-virtual {v0, v2, p1}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    const-string v3, "collect_build_ids"

    .line 106
    .line 107
    invoke-virtual {v0, v3, p1}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    new-instance v7, Lc8/g;

    .line 112
    .line 113
    invoke-direct {v7, v1, v2, p1}, Lc8/g;-><init>(ZZZ)V

    .line 114
    .line 115
    .line 116
    int-to-long p0, p0

    .line 117
    const-string v0, "expires_at"

    .line 118
    .line 119
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-eqz v1, :cond_1

    .line 124
    .line 125
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->optLong(Ljava/lang/String;)J

    .line 126
    .line 127
    .line 128
    move-result-wide p0

    .line 129
    :goto_2
    move-wide v4, p0

    .line 130
    goto :goto_3

    .line 131
    :cond_1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 132
    .line 133
    .line 134
    move-result-wide v0

    .line 135
    const-wide/16 v2, 0x3e8

    .line 136
    .line 137
    mul-long/2addr p0, v2

    .line 138
    add-long/2addr p0, v0

    .line 139
    goto :goto_2

    .line 140
    :goto_3
    new-instance v3, Lus/a;

    .line 141
    .line 142
    invoke-direct/range {v3 .. v12}, Lus/a;-><init>(JLc1/l2;Lc8/g;DDI)V

    .line 143
    .line 144
    .line 145
    return-object v3
.end method

.method public now()Lmy0/f;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "now(...)"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lmy0/f;->f:Lmy0/f;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/time/Instant;->getEpochSecond()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    invoke-virtual {p0}, Ljava/time/Instant;->getNano()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0, v0, v1}, Lmy0/h;->i(IJ)Lmy0/f;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
