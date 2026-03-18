.class public final Lgw0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgw0/a;


# static fields
.field public static final e:Lgw0/g;

.field public static final f:Lgw0/g;

.field public static final g:Lgw0/g;

.field public static final h:Lgw0/g;

.field public static final i:Lgw0/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgw0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lgw0/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lgw0/g;->e:Lgw0/g;

    .line 8
    .line 9
    new-instance v0, Lgw0/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lgw0/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lgw0/g;->f:Lgw0/g;

    .line 16
    .line 17
    new-instance v0, Lgw0/g;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lgw0/g;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lgw0/g;->g:Lgw0/g;

    .line 24
    .line 25
    new-instance v0, Lgw0/g;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lgw0/g;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lgw0/g;->h:Lgw0/g;

    .line 32
    .line 33
    new-instance v0, Lgw0/g;

    .line 34
    .line 35
    const/4 v1, 0x4

    .line 36
    invoke-direct {v0, v1}, Lgw0/g;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lgw0/g;->i:Lgw0/g;

    .line 40
    .line 41
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lgw0/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lzv0/c;Lrx0/i;)V
    .locals 3

    .line 1
    iget p0, p0, Lgw0/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Lay0/q;

    .line 7
    .line 8
    const-string p0, "client"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lzv0/c;->j:Llw0/a;

    .line 14
    .line 15
    sget-object p1, Llw0/a;->l:Lj51/i;

    .line 16
    .line 17
    new-instance v0, Lgb0/z;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x3

    .line 21
    invoke-direct {v0, p2, v1, v2}, Lgb0/z;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    check-cast p2, Lay0/q;

    .line 29
    .line 30
    const-string p0, "client"

    .line 31
    .line 32
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 36
    .line 37
    sget-object p1, Lkw0/e;->i:Lj51/i;

    .line 38
    .line 39
    new-instance v0, La7/l0;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    const/4 v2, 0x6

    .line 43
    invoke-direct {v0, p2, v1, v2}, La7/l0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :pswitch_1
    check-cast p2, Lay0/n;

    .line 51
    .line 52
    const-string p0, "client"

    .line 53
    .line 54
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 58
    .line 59
    sget-object p1, Lkw0/e;->g:Lj51/i;

    .line 60
    .line 61
    new-instance v0, La7/l0;

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    const/4 v2, 0x5

    .line 65
    invoke-direct {v0, p2, v1, v2}, La7/l0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_2
    check-cast p2, Lay0/o;

    .line 73
    .line 74
    const-string p0, "client"

    .line 75
    .line 76
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    sget-object p0, Lfw0/w0;->b:Lfw0/a;

    .line 80
    .line 81
    invoke-static {p1, p0}, Lfw0/u;->a(Lzv0/c;Lfw0/t;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    if-eqz v0, :cond_0

    .line 86
    .line 87
    check-cast v0, Lfw0/w0;

    .line 88
    .line 89
    new-instance p0, Lac/k;

    .line 90
    .line 91
    const/4 v1, 0x0

    .line 92
    invoke-direct {p0, p2, p1, v1}, Lac/k;-><init>(Lay0/o;Lzv0/c;Lkotlin/coroutines/Continuation;)V

    .line 93
    .line 94
    .line 95
    iget-object p1, v0, Lfw0/w0;->a:Ljava/util/ArrayList;

    .line 96
    .line 97
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 102
    .line 103
    new-instance p2, Ljava/lang/StringBuilder;

    .line 104
    .line 105
    const-string v0, "Plugin "

    .line 106
    .line 107
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string p0, " is not installed. Consider using `install("

    .line 114
    .line 115
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    sget-object p0, Lfw0/w0;->c:Lvw0/a;

    .line 119
    .line 120
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string p0, ")` in client config first."

    .line 124
    .line 125
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw p1

    .line 136
    :pswitch_3
    check-cast p2, Lay0/p;

    .line 137
    .line 138
    const-string p0, "client"

    .line 139
    .line 140
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p1, Lzv0/c;->i:Lkw0/e;

    .line 144
    .line 145
    sget-object p1, Lkw0/e;->h:Lj51/i;

    .line 146
    .line 147
    new-instance v0, La7/l0;

    .line 148
    .line 149
    const/4 v1, 0x0

    .line 150
    const/4 v2, 0x4

    .line 151
    invoke-direct {v0, p2, v1, v2}, La7/l0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p0, p1, v0}, Lyw0/d;->f(Lj51/i;Lay0/o;)V

    .line 155
    .line 156
    .line 157
    return-void

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
