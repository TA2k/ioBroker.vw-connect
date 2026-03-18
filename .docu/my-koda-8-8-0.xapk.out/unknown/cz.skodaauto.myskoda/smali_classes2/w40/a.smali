.class public final Lw40/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw40/d;


# direct methods
.method public synthetic constructor <init>(Lw40/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw40/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw40/a;->e:Lw40/d;

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
    .locals 7

    .line 1
    iget p2, p0, Lw40/a;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lon0/r;

    .line 7
    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    iget-object p0, p0, Lw40/a;->e:Lw40/d;

    .line 11
    .line 12
    iget-object p2, p0, Lw40/d;->i:Lnn0/v;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lw40/c;

    .line 19
    .line 20
    iget-object p0, p0, Lw40/c;->e:Lon0/u;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lon0/u;->a:Ljava/lang/String;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    :goto_0
    const/16 v0, 0x17f

    .line 29
    .line 30
    invoke-static {p1, p0, v0}, Lon0/r;->a(Lon0/r;Ljava/lang/String;I)Lon0/r;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p2, p0}, Lnn0/v;->a(Lon0/r;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    check-cast p1, Lon0/r;

    .line 41
    .line 42
    if-eqz p1, :cond_3

    .line 43
    .line 44
    iget-object p1, p1, Lon0/r;->f:Lon0/s;

    .line 45
    .line 46
    if-eqz p1, :cond_3

    .line 47
    .line 48
    iget-object p1, p1, Lon0/s;->a:Lon0/v;

    .line 49
    .line 50
    if-eqz p1, :cond_3

    .line 51
    .line 52
    iget-object p0, p0, Lw40/a;->e:Lw40/d;

    .line 53
    .line 54
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    move-object v0, p2

    .line 59
    check-cast v0, Lw40/c;

    .line 60
    .line 61
    iget-object v1, p1, Lon0/v;->a:Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 64
    .line 65
    .line 66
    move-result p2

    .line 67
    const/16 v2, 0x50

    .line 68
    .line 69
    if-ge p2, v2, :cond_2

    .line 70
    .line 71
    const/4 p2, 0x1

    .line 72
    :goto_1
    move v2, p2

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 p2, 0x0

    .line 75
    goto :goto_1

    .line 76
    :goto_2
    iget-object v3, p1, Lon0/v;->b:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v4, p1, Lon0/v;->c:Ljava/util/ArrayList;

    .line 79
    .line 80
    const/4 v5, 0x0

    .line 81
    const/16 v6, 0x10

    .line 82
    .line 83
    invoke-static/range {v0 .. v6}, Lw40/c;->a(Lw40/c;Ljava/lang/String;ZLjava/lang/String;Ljava/util/ArrayList;Lon0/u;I)Lw40/c;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 88
    .line 89
    .line 90
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
