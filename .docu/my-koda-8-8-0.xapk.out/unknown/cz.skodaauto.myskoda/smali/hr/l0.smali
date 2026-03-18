.class public final Lhr/l0;
.super Lhr/l1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public e:Ljava/lang/Object;

.field public final synthetic f:I

.field public final g:Ljava/util/Iterator;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x2

    .line 2
    iput v0, p0, Lhr/l0;->d:I

    return-void
.end method

.method public constructor <init>(Ljava/util/Iterator;Lgr/h;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lhr/l0;->f:I

    .line 3
    iput-object p1, p0, Lhr/l0;->g:Ljava/util/Iterator;

    iput-object p2, p0, Lhr/l0;->h:Ljava/lang/Object;

    invoke-direct {p0}, Lhr/l0;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/util/Set;Ljava/util/Set;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lhr/l0;->f:I

    .line 4
    iput-object p2, p0, Lhr/l0;->h:Ljava/lang/Object;

    invoke-direct {p0}, Lhr/l0;-><init>()V

    .line 5
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Lhr/l0;->g:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 4

    .line 1
    iget v0, p0, Lhr/l0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    if-eq v0, v1, :cond_6

    .line 5
    .line 6
    invoke-static {v0}, Lu/w;->o(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v0, :cond_5

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    if-eq v0, v3, :cond_4

    .line 15
    .line 16
    iput v1, p0, Lhr/l0;->d:I

    .line 17
    .line 18
    iget v0, p0, Lhr/l0;->f:I

    .line 19
    .line 20
    packed-switch v0, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    :cond_0
    iget-object v0, p0, Lhr/l0;->g:Ljava/util/Iterator;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget-object v1, p0, Lhr/l0;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Ljava/util/Set;

    .line 38
    .line 39
    invoke-interface {v1, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/4 v0, 0x3

    .line 47
    iput v0, p0, Lhr/l0;->d:I

    .line 48
    .line 49
    :goto_0
    const/4 v0, 0x0

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    :pswitch_0
    iget-object v0, p0, Lhr/l0;->g:Ljava/util/Iterator;

    .line 52
    .line 53
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_3

    .line 58
    .line 59
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    iget-object v1, p0, Lhr/l0;->h:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v1, Lgr/h;

    .line 66
    .line 67
    invoke-interface {v1, v0}, Lgr/h;->apply(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_2

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    const/4 v0, 0x3

    .line 75
    iput v0, p0, Lhr/l0;->d:I

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :goto_1
    iput-object v0, p0, Lhr/l0;->e:Ljava/lang/Object;

    .line 79
    .line 80
    iget v0, p0, Lhr/l0;->d:I

    .line 81
    .line 82
    const/4 v1, 0x3

    .line 83
    if-eq v0, v1, :cond_4

    .line 84
    .line 85
    iput v2, p0, Lhr/l0;->d:I

    .line 86
    .line 87
    return v2

    .line 88
    :cond_4
    const/4 p0, 0x0

    .line 89
    return p0

    .line 90
    :cond_5
    return v2

    .line 91
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lhr/l0;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x2

    .line 8
    iput v0, p0, Lhr/l0;->d:I

    .line 9
    .line 10
    iget-object v0, p0, Lhr/l0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    iput-object v1, p0, Lhr/l0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0
.end method
