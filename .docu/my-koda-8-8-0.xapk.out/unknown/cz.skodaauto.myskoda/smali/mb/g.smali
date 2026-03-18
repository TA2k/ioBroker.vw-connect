.class public final synthetic Lmb/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lmb/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lmb/g;->f:I

    iput-object p2, p0, Lmb/g;->e:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 2
    iput p3, p0, Lmb/g;->d:I

    iput-object p1, p0, Lmb/g;->e:Ljava/lang/String;

    iput p2, p0, Lmb/g;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lmb/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lmb/g;->f:I

    .line 7
    .line 8
    iget-object p0, p0, Lmb/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    check-cast p1, Lua/a;

    .line 11
    .line 12
    const-string v1, "_connection"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "UPDATE workspec SET stop_reason=? WHERE id=?"

    .line 18
    .line 19
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    const/4 v1, 0x1

    .line 24
    int-to-long v2, v0

    .line 25
    :try_start_0
    invoke-interface {p1, v1, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    .line 35
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_0
    iget-object v0, p0, Lmb/g;->e:Ljava/lang/String;

    .line 47
    .line 48
    iget p0, p0, Lmb/g;->f:I

    .line 49
    .line 50
    check-cast p1, Lua/a;

    .line 51
    .line 52
    const-string v1, "_connection"

    .line 53
    .line 54
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, "UPDATE workspec SET next_schedule_time_override=9223372036854775807 WHERE (id=? AND next_schedule_time_override_generation=?)"

    .line 58
    .line 59
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    const/4 v1, 0x1

    .line 64
    :try_start_1
    invoke-interface {p1, v1, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 65
    .line 66
    .line 67
    const/4 v0, 0x2

    .line 68
    int-to-long v1, p0

    .line 69
    invoke-interface {p1, v0, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 70
    .line 71
    .line 72
    invoke-interface {p1}, Lua/c;->s0()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 73
    .line 74
    .line 75
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :catchall_1
    move-exception p0

    .line 80
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :pswitch_1
    iget-object v0, p0, Lmb/g;->e:Ljava/lang/String;

    .line 85
    .line 86
    iget p0, p0, Lmb/g;->f:I

    .line 87
    .line 88
    check-cast p1, Lua/a;

    .line 89
    .line 90
    const-string v1, "_connection"

    .line 91
    .line 92
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    const-string v1, "SELECT * FROM SystemIdInfo WHERE work_spec_id=? AND generation=?"

    .line 96
    .line 97
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    const/4 v1, 0x1

    .line 102
    :try_start_2
    invoke-interface {p1, v1, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 103
    .line 104
    .line 105
    const/4 v0, 0x2

    .line 106
    int-to-long v1, p0

    .line 107
    invoke-interface {p1, v0, v1, v2}, Lua/c;->bindLong(IJ)V

    .line 108
    .line 109
    .line 110
    const-string p0, "work_spec_id"

    .line 111
    .line 112
    invoke-static {p1, p0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    const-string v0, "generation"

    .line 117
    .line 118
    invoke-static {p1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    const-string v1, "system_id"

    .line 123
    .line 124
    invoke-static {p1, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    if-eqz v2, :cond_0

    .line 133
    .line 134
    invoke-interface {p1, p0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-interface {p1, v0}, Lua/c;->getLong(I)J

    .line 139
    .line 140
    .line 141
    move-result-wide v2

    .line 142
    long-to-int v0, v2

    .line 143
    invoke-interface {p1, v1}, Lua/c;->getLong(I)J

    .line 144
    .line 145
    .line 146
    move-result-wide v1

    .line 147
    long-to-int v1, v1

    .line 148
    new-instance v2, Lmb/f;

    .line 149
    .line 150
    invoke-direct {v2, p0, v0, v1}, Lmb/f;-><init>(Ljava/lang/String;II)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 151
    .line 152
    .line 153
    goto :goto_1

    .line 154
    :catchall_2
    move-exception p0

    .line 155
    goto :goto_2

    .line 156
    :cond_0
    const/4 v2, 0x0

    .line 157
    :goto_1
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 158
    .line 159
    .line 160
    return-object v2

    .line 161
    :goto_2
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 162
    .line 163
    .line 164
    throw p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
