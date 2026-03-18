.class public final synthetic Lmb/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(JLjava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lmb/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Lmb/p;->f:Ljava/lang/String;

    iput-wide p1, p0, Lmb/p;->e:J

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/String;I)V
    .locals 0

    .line 2
    iput p4, p0, Lmb/p;->d:I

    iput-wide p1, p0, Lmb/p;->e:J

    iput-object p3, p0, Lmb/p;->f:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lmb/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lzb/u0;

    .line 7
    .line 8
    const-string v0, "$this$wthReferences"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lzb/u0;->b:Landroid/content/Context;

    .line 14
    .line 15
    iget-wide v0, p0, Lmb/p;->e:J

    .line 16
    .line 17
    invoke-static {v0, v1}, Le3/j0;->z(J)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/high16 v1, -0x1000000

    .line 22
    .line 23
    or-int/2addr v0, v1

    .line 24
    new-instance v1, Lvv0/d;

    .line 25
    .line 26
    invoke-direct {v1}, Lvv0/d;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v2, Landroid/os/Bundle;

    .line 30
    .line 31
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 32
    .line 33
    .line 34
    const-string v3, "android.support.customtabs.extra.TOOLBAR_COLOR"

    .line 35
    .line 36
    invoke-virtual {v2, v3, v0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    iput-object v2, v1, Lvv0/d;->e:Ljava/lang/Object;

    .line 40
    .line 41
    iget-object v0, v1, Lvv0/d;->b:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Landroid/content/Intent;

    .line 44
    .line 45
    const-string v2, "android.support.customtabs.extra.TITLE_VISIBILITY"

    .line 46
    .line 47
    const/4 v3, 0x1

    .line 48
    invoke-virtual {v0, v2, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Lvv0/d;->c()Lc2/k;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iget-object p0, p0, Lmb/p;->f:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    iget-object v1, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v1, Landroid/content/Intent;

    .line 64
    .line 65
    invoke-virtual {v1, p0}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 66
    .line 67
    .line 68
    iget-object p0, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Landroid/os/Bundle;

    .line 71
    .line 72
    invoke-virtual {p1, v1, p0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_0
    iget-wide v0, p0, Lmb/p;->e:J

    .line 79
    .line 80
    iget-object p0, p0, Lmb/p;->f:Ljava/lang/String;

    .line 81
    .line 82
    check-cast p1, Lua/a;

    .line 83
    .line 84
    const-string v2, "_connection"

    .line 85
    .line 86
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string v2, "UPDATE workspec SET last_enqueue_time=? WHERE id=?"

    .line 90
    .line 91
    invoke-interface {p1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    const/4 v2, 0x1

    .line 96
    :try_start_0
    invoke-interface {p1, v2, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 97
    .line 98
    .line 99
    const/4 v0, 0x2

    .line 100
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-interface {p1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    .line 105
    .line 106
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 107
    .line 108
    .line 109
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object p0

    .line 112
    :catchall_0
    move-exception p0

    .line 113
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :pswitch_1
    iget-wide v0, p0, Lmb/p;->e:J

    .line 118
    .line 119
    iget-object p0, p0, Lmb/p;->f:Ljava/lang/String;

    .line 120
    .line 121
    check-cast p1, Lua/a;

    .line 122
    .line 123
    const-string v2, "_connection"

    .line 124
    .line 125
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    const-string v2, "UPDATE workspec SET schedule_requested_at=? WHERE id=?"

    .line 129
    .line 130
    invoke-interface {p1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    const/4 v3, 0x1

    .line 135
    :try_start_1
    invoke-interface {v2, v3, v0, v1}, Lua/c;->bindLong(IJ)V

    .line 136
    .line 137
    .line 138
    const/4 v0, 0x2

    .line 139
    invoke-interface {v2, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 143
    .line 144
    .line 145
    invoke-static {p1}, Ljp/ze;->b(Lua/a;)I

    .line 146
    .line 147
    .line 148
    move-result p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 149
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 150
    .line 151
    .line 152
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    return-object p0

    .line 157
    :catchall_1
    move-exception p0

    .line 158
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    nop

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
