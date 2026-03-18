.class public final Lz4/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lrx/b;

.field public b:Z

.field public final c:Ljava/util/HashMap;

.field public final d:Ljava/util/HashMap;

.field public final e:Ljava/util/HashMap;

.field public final f:Le5/b;

.field public g:I

.field public final h:Ljava/util/ArrayList;

.field public final i:Ljava/util/ArrayList;

.field public j:Z

.field public final k:Lt4/c;

.field public l:J


# direct methods
.method public constructor <init>(Lt4/c;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lz4/q;->b:Z

    .line 6
    .line 7
    new-instance v1, Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lz4/q;->c:Ljava/util/HashMap;

    .line 13
    .line 14
    new-instance v2, Ljava/util/HashMap;

    .line 15
    .line 16
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v2, p0, Lz4/q;->d:Ljava/util/HashMap;

    .line 20
    .line 21
    new-instance v2, Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v2, p0, Lz4/q;->e:Ljava/util/HashMap;

    .line 27
    .line 28
    new-instance v2, Le5/b;

    .line 29
    .line 30
    invoke-direct {v2, p0}, Le5/b;-><init>(Lz4/q;)V

    .line 31
    .line 32
    .line 33
    iput-object v2, p0, Lz4/q;->f:Le5/b;

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    iput v3, p0, Lz4/q;->g:I

    .line 41
    .line 42
    new-instance v5, Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v5, p0, Lz4/q;->h:Ljava/util/ArrayList;

    .line 48
    .line 49
    new-instance v5, Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 52
    .line 53
    .line 54
    iput-object v5, p0, Lz4/q;->i:Ljava/util/ArrayList;

    .line 55
    .line 56
    iput-boolean v0, p0, Lz4/q;->j:Z

    .line 57
    .line 58
    iput-object v4, v2, Le5/b;->a:Ljava/lang/Object;

    .line 59
    .line 60
    invoke-virtual {v1, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    iput-object p1, p0, Lz4/q;->k:Lt4/c;

    .line 64
    .line 65
    const/16 p1, 0xf

    .line 66
    .line 67
    invoke-static {v3, v3, p1}, Lt4/b;->b(III)J

    .line 68
    .line 69
    .line 70
    move-result-wide v0

    .line 71
    iput-wide v0, p0, Lz4/q;->l:J

    .line 72
    .line 73
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 74
    .line 75
    new-instance p1, Lrx/b;

    .line 76
    .line 77
    const/16 v0, 0x18

    .line 78
    .line 79
    invoke-direct {p1, p0, v0}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 80
    .line 81
    .line 82
    iput-object p1, p0, Lz4/q;->a:Lrx/b;

    .line 83
    .line 84
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lz4/q;->h:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    iput-boolean p1, p0, Lz4/q;->j:Z

    .line 8
    .line 9
    return-void
.end method

.method public final b(Ljava/lang/Object;)Le5/b;
    .locals 2

    .line 1
    iget-object v0, p0, Lz4/q;->c:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Le5/i;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Le5/b;

    .line 12
    .line 13
    invoke-direct {v1, p0}, Le5/b;-><init>(Lz4/q;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    iput-object p1, v1, Le5/b;->a:Ljava/lang/Object;

    .line 20
    .line 21
    :cond_0
    instance-of p0, v1, Le5/b;

    .line 22
    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    check-cast v1, Le5/b;

    .line 26
    .line 27
    return-object v1

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method public final c(Ljava/lang/Float;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final d(ILjava/lang/String;)Lf5/g;
    .locals 2

    .line 1
    invoke-virtual {p0, p2}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, v0, Le5/b;->c:Ljava/lang/Object;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    instance-of v1, v1, Lf5/g;

    .line 10
    .line 11
    if-nez v1, :cond_1

    .line 12
    .line 13
    :cond_0
    new-instance v1, Lf5/g;

    .line 14
    .line 15
    invoke-direct {v1, p0}, Lf5/g;-><init>(Lz4/q;)V

    .line 16
    .line 17
    .line 18
    iput p1, v1, Lf5/g;->b:I

    .line 19
    .line 20
    iput-object p2, v1, Lf5/g;->g:Ljava/lang/String;

    .line 21
    .line 22
    iput-object v1, v0, Le5/b;->c:Ljava/lang/Object;

    .line 23
    .line 24
    invoke-virtual {v1}, Lf5/g;->b()Lh5/d;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {v0, p0}, Le5/b;->a(Lh5/d;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    iget-object p0, v0, Le5/b;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lf5/g;

    .line 34
    .line 35
    return-object p0
.end method

.method public final e(I)Le5/h;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "__HELPER_KEY_"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lz4/q;->g:I

    .line 9
    .line 10
    add-int/lit8 v2, v1, 0x1

    .line 11
    .line 12
    iput v2, p0, Lz4/q;->g:I

    .line 13
    .line 14
    const-string v2, "__"

    .line 15
    .line 16
    invoke-static {v1, v2, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iget-object v1, p0, Lz4/q;->d:Ljava/util/HashMap;

    .line 21
    .line 22
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Le5/h;

    .line 27
    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    invoke-static {p1}, Lu/w;->o(I)I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    const/high16 v3, 0x3f000000    # 0.5f

    .line 35
    .line 36
    const/4 v4, 0x4

    .line 37
    packed-switch v2, :pswitch_data_0

    .line 38
    .line 39
    .line 40
    :pswitch_0
    new-instance v2, Le5/h;

    .line 41
    .line 42
    invoke-direct {v2, p0, p1}, Le5/h;-><init>(Lz4/q;I)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    new-instance v2, Lf5/f;

    .line 47
    .line 48
    invoke-direct {v2, p0, p1}, Lf5/f;-><init>(Lz4/q;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_2
    new-instance v2, Lf5/e;

    .line 53
    .line 54
    invoke-direct {v2, p0, p1}, Lf5/e;-><init>(Lz4/q;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_3
    new-instance v2, Lf5/b;

    .line 59
    .line 60
    const/4 p1, 0x5

    .line 61
    invoke-direct {v2, p0, p1}, Le5/h;-><init>(Lz4/q;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :pswitch_4
    new-instance v2, Lf5/a;

    .line 66
    .line 67
    const/4 p1, 0x1

    .line 68
    invoke-direct {v2, p0, v4, p1}, Lf5/a;-><init>(Lz4/q;II)V

    .line 69
    .line 70
    .line 71
    iput v3, v2, Lf5/a;->o0:F

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_5
    new-instance v2, Lf5/a;

    .line 75
    .line 76
    const/4 p1, 0x0

    .line 77
    invoke-direct {v2, p0, v4, p1}, Lf5/a;-><init>(Lz4/q;II)V

    .line 78
    .line 79
    .line 80
    iput v3, v2, Lf5/a;->o0:F

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_6
    new-instance v2, Lf5/i;

    .line 84
    .line 85
    const/4 p1, 0x2

    .line 86
    invoke-direct {v2, p0, p1}, Lf5/c;-><init>(Lz4/q;I)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :pswitch_7
    new-instance v2, Lf5/h;

    .line 91
    .line 92
    const/4 p1, 0x1

    .line 93
    invoke-direct {v2, p0, p1}, Lf5/c;-><init>(Lz4/q;I)V

    .line 94
    .line 95
    .line 96
    :goto_0
    iput-object v0, v2, Le5/b;->a:Ljava/lang/Object;

    .line 97
    .line 98
    invoke-virtual {v1, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    :cond_0
    return-object v2

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch
.end method
