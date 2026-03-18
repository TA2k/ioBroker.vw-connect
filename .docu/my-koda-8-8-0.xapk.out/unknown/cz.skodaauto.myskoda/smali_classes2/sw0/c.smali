.class public final Lsw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/i;

.field public final synthetic f:Ljava/lang/Comparable;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lyy0/i;Ljava/lang/Comparable;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lsw0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsw0/c;->e:Lyy0/i;

    .line 4
    .line 5
    iput-object p2, p0, Lsw0/c;->f:Ljava/lang/Comparable;

    .line 6
    .line 7
    iput-object p3, p0, Lsw0/c;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lsw0/c;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lsw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Le1/b0;

    .line 7
    .line 8
    iget-object v0, p0, Lsw0/c;->f:Ljava/lang/Comparable;

    .line 9
    .line 10
    move-object v3, v0

    .line 11
    check-cast v3, Ljava/lang/String;

    .line 12
    .line 13
    iget-object v0, p0, Lsw0/c;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Lve0/u;

    .line 17
    .line 18
    iget-object v0, p0, Lsw0/c;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v5, v0

    .line 21
    check-cast v5, Ljava/lang/String;

    .line 22
    .line 23
    const/4 v6, 0x4

    .line 24
    move-object v2, p1

    .line 25
    invoke-direct/range {v1 .. v6}, Le1/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lsw0/c;->e:Lyy0/i;

    .line 29
    .line 30
    invoke-interface {p0, v1, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    if-ne p0, p1, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    :goto_0
    return-object p0

    .line 42
    :pswitch_0
    move-object v1, p1

    .line 43
    iget-object p1, p0, Lsw0/c;->e:Lyy0/i;

    .line 44
    .line 45
    check-cast p1, Lam0/i;

    .line 46
    .line 47
    new-instance v0, Lsw0/b;

    .line 48
    .line 49
    iget-object v2, p0, Lsw0/c;->f:Ljava/lang/Comparable;

    .line 50
    .line 51
    check-cast v2, Ljava/nio/charset/Charset;

    .line 52
    .line 53
    iget-object v3, p0, Lsw0/c;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v3, Lzw0/a;

    .line 56
    .line 57
    iget-object p0, p0, Lsw0/c;->h:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v4, p0

    .line 60
    check-cast v4, Lio/ktor/utils/io/t;

    .line 61
    .line 62
    const/4 v5, 0x1

    .line 63
    invoke-direct/range {v0 .. v5}, Lsw0/b;-><init>(Lyy0/j;Ljava/nio/charset/Charset;Lzw0/a;Lio/ktor/utils/io/t;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v0, p2}, Lam0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 71
    .line 72
    if-ne p0, p1, :cond_1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    :goto_1
    return-object p0

    .line 78
    :pswitch_1
    move-object v1, p1

    .line 79
    iget-object p1, p0, Lsw0/c;->e:Lyy0/i;

    .line 80
    .line 81
    check-cast p1, Lam0/i;

    .line 82
    .line 83
    new-instance v0, Lsw0/b;

    .line 84
    .line 85
    iget-object v2, p0, Lsw0/c;->f:Ljava/lang/Comparable;

    .line 86
    .line 87
    check-cast v2, Ljava/nio/charset/Charset;

    .line 88
    .line 89
    iget-object v3, p0, Lsw0/c;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v3, Lzw0/a;

    .line 92
    .line 93
    iget-object p0, p0, Lsw0/c;->h:Ljava/lang/Object;

    .line 94
    .line 95
    move-object v4, p0

    .line 96
    check-cast v4, Lio/ktor/utils/io/t;

    .line 97
    .line 98
    const/4 v5, 0x0

    .line 99
    invoke-direct/range {v0 .. v5}, Lsw0/b;-><init>(Lyy0/j;Ljava/nio/charset/Charset;Lzw0/a;Lio/ktor/utils/io/t;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v0, p2}, Lam0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    if-ne p0, p1, :cond_2

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    :goto_2
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
