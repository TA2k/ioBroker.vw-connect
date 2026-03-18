.class public final Lfv/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld0/b;
.implements Laq/f;
.implements Lgs/e;
.implements Lop/b;
.implements Lvp/u;
.implements Lpx0/f;
.implements Lxo/a;


# static fields
.field public static final synthetic e:Lfv/b;

.field public static final synthetic f:Lfv/b;

.field public static final synthetic g:Lfv/b;

.field public static final synthetic h:Lfv/b;

.field public static final synthetic i:Lfv/b;

.field public static final synthetic j:Lfv/b;

.field public static final synthetic k:Lfv/b;

.field public static final synthetic l:Lfv/b;

.field public static final synthetic m:Lfv/b;

.field public static final synthetic n:Lfv/b;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lfv/b;->e:Lfv/b;

    .line 9
    .line 10
    new-instance v0, Lfv/b;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lfv/b;->f:Lfv/b;

    .line 18
    .line 19
    new-instance v0, Lfv/b;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lfv/b;->g:Lfv/b;

    .line 27
    .line 28
    new-instance v0, Lfv/b;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lfv/b;->h:Lfv/b;

    .line 36
    .line 37
    new-instance v0, Lfv/b;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lfv/b;->i:Lfv/b;

    .line 45
    .line 46
    new-instance v0, Lfv/b;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lfv/b;->j:Lfv/b;

    .line 54
    .line 55
    new-instance v0, Lfv/b;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lfv/b;->k:Lfv/b;

    .line 63
    .line 64
    new-instance v0, Lfv/b;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lfv/b;->l:Lfv/b;

    .line 72
    .line 73
    new-instance v0, Lfv/b;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lfv/b;->m:Lfv/b;

    .line 81
    .line 82
    new-instance v0, Lfv/b;

    .line 83
    .line 84
    const/16 v1, 0x1a

    .line 85
    .line 86
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Lfv/b;->n:Lfv/b;

    .line 90
    .line 91
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lfv/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    const/4 p1, 0x1

    iput p1, p0, Lfv/b;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final b(Lu01/y;)Z
    .locals 2

    .line 1
    sget-object v0, Lv01/g;->i:Lu01/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu01/y;->b()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, ".class"

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-static {p0, v0, v1}, Lly0/w;->o(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    xor-int/2addr p0, v1

    .line 15
    return p0
.end method


# virtual methods
.method public a(Lh0/z1;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public varargs c([Ljava/lang/Object;)Ljava/lang/String;
    .locals 7

    .line 1
    const-string v0, "components"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string p0, ", "

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/4 v5, 0x0

    .line 28
    const/16 v6, 0x3d

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    move-object v1, p1

    .line 33
    invoke-static/range {v1 .. v6}, Lmx0/n;->H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Lfv/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lpv/e;

    .line 7
    .line 8
    const-class v0, Lpv/f;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lpv/f;

    .line 15
    .line 16
    const-class v1, Lfv/d;

    .line 17
    .line 18
    invoke-virtual {p1, v1}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lfv/d;

    .line 23
    .line 24
    invoke-direct {p0, v0, p1}, Lpv/e;-><init>(Lpv/f;Lfv/d;)V

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    new-instance p0, Llv/b;

    .line 29
    .line 30
    const-class v0, Llv/d;

    .line 31
    .line 32
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Llv/d;

    .line 37
    .line 38
    const-class v1, Lfv/d;

    .line 39
    .line 40
    invoke-virtual {p1, v1}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lfv/d;

    .line 45
    .line 46
    const-class v2, Lfv/f;

    .line 47
    .line 48
    invoke-virtual {p1, v2}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Lfv/f;

    .line 53
    .line 54
    invoke-direct {p0, v0, v1, p1}, Llv/b;-><init>(Llv/d;Lfv/d;Lfv/f;)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lfv/b;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/u8;->e:Lcom/google/android/gms/internal/measurement/u8;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/u8;->b()Lcom/google/android/gms/internal/measurement/v8;

    .line 11
    .line 12
    .line 13
    sget-object p0, Lcom/google/android/gms/internal/measurement/w8;->d:Lcom/google/android/gms/internal/measurement/n4;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 26
    .line 27
    sget-object p0, Lcom/google/android/gms/internal/measurement/w7;->e:Lcom/google/android/gms/internal/measurement/w7;

    .line 28
    .line 29
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/w7;->d:Lgr/p;

    .line 30
    .line 31
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lcom/google/android/gms/internal/measurement/x7;

    .line 34
    .line 35
    sget-object p0, Lcom/google/android/gms/internal/measurement/y7;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 36
    .line 37
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 48
    .line 49
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 52
    .line 53
    .line 54
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->v:Lcom/google/android/gms/internal/measurement/n4;

    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    check-cast p0, Ljava/lang/Long;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 63
    .line 64
    .line 65
    move-result-wide v0

    .line 66
    long-to-int p0, v0

    .line 67
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 73
    .line 74
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 75
    .line 76
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 77
    .line 78
    .line 79
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->c0:Lcom/google/android/gms/internal/measurement/n4;

    .line 80
    .line 81
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Ljava/lang/String;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 89
    .line 90
    sget-object p0, Lcom/google/android/gms/internal/measurement/r8;->e:Lcom/google/android/gms/internal/measurement/r8;

    .line 91
    .line 92
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/r8;->a()Lcom/google/android/gms/internal/measurement/s8;

    .line 93
    .line 94
    .line 95
    sget-object p0, Lcom/google/android/gms/internal/measurement/t8;->e:Lcom/google/android/gms/internal/measurement/n4;

    .line 96
    .line 97
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    check-cast p0, Ljava/lang/Long;

    .line 102
    .line 103
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 108
    .line 109
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 110
    .line 111
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 112
    .line 113
    .line 114
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->g0:Lcom/google/android/gms/internal/measurement/n4;

    .line 115
    .line 116
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    check-cast p0, Ljava/lang/Long;

    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 127
    .line 128
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 129
    .line 130
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 131
    .line 132
    .line 133
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->R:Lcom/google/android/gms/internal/measurement/n4;

    .line 134
    .line 135
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Ljava/lang/Long;

    .line 140
    .line 141
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_7
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 146
    .line 147
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 148
    .line 149
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 150
    .line 151
    .line 152
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->u0:Lcom/google/android/gms/internal/measurement/n4;

    .line 153
    .line 154
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    check-cast p0, Ljava/lang/String;

    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_8
    sget-object p0, Lcom/google/android/gms/internal/measurement/f8;->e:Lcom/google/android/gms/internal/measurement/f8;

    .line 162
    .line 163
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f8;->d:Lgr/p;

    .line 164
    .line 165
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p0, Lcom/google/android/gms/internal/measurement/g8;

    .line 168
    .line 169
    sget-object p0, Lcom/google/android/gms/internal/measurement/h8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 170
    .line 171
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    check-cast p0, Ljava/lang/Boolean;

    .line 176
    .line 177
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 178
    .line 179
    .line 180
    move-result p0

    .line 181
    new-instance v0, Ljava/lang/Boolean;

    .line 182
    .line 183
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 184
    .line 185
    .line 186
    return-object v0

    .line 187
    :pswitch_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :pswitch_data_0
    .packed-switch 0xb
        :pswitch_9
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public synthetic o(Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 1

    .line 1
    const-string p0, "OptionalModuleUtils"

    .line 2
    .line 3
    const-string v0, "Failed to request modules install request"

    .line 4
    .line 5
    invoke-static {p0, v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lfv/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const-string p0, "CompositionErrorContext"

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x19
        :pswitch_0
    .end packed-switch
.end method
