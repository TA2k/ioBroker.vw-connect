.class public final synthetic Lk01/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lk01/p;ILu01/f;IZ)V
    .locals 0

    .line 1
    const/4 p5, 0x0

    iput p5, p0, Lk01/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk01/k;->g:Ljava/lang/Object;

    iput p2, p0, Lk01/k;->e:I

    iput-object p3, p0, Lk01/k;->h:Ljava/lang/Object;

    iput p4, p0, Lk01/k;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Llz0/o;Ljava/lang/CharSequence;II)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lk01/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk01/k;->g:Ljava/lang/Object;

    iput-object p2, p0, Lk01/k;->h:Ljava/lang/Object;

    iput p3, p0, Lk01/k;->e:I

    iput p4, p0, Lk01/k;->f:I

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lk01/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk01/k;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Llz0/o;

    .line 9
    .line 10
    iget-object v1, p0, Lk01/k;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/lang/CharSequence;

    .line 13
    .line 14
    iget v2, p0, Lk01/k;->e:I

    .line 15
    .line 16
    iget p0, p0, Lk01/k;->f:I

    .line 17
    .line 18
    new-instance v3, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v4, "Expected "

    .line 21
    .line 22
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Llz0/o;->a:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, " but got "

    .line 31
    .line 32
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    add-int/2addr p0, v2

    .line 36
    add-int/lit8 p0, p0, 0x1

    .line 37
    .line 38
    invoke-interface {v1, v2, p0}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :pswitch_0
    iget-object v0, p0, Lk01/k;->g:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Lk01/p;

    .line 57
    .line 58
    iget v1, p0, Lk01/k;->e:I

    .line 59
    .line 60
    iget-object v2, p0, Lk01/k;->h:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v2, Lu01/f;

    .line 63
    .line 64
    iget p0, p0, Lk01/k;->f:I

    .line 65
    .line 66
    :try_start_0
    iget-object v3, v0, Lk01/p;->n:Lk01/a0;

    .line 67
    .line 68
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    int-to-long v3, p0

    .line 72
    invoke-virtual {v2, v3, v4}, Lu01/f;->skip(J)V

    .line 73
    .line 74
    .line 75
    iget-object p0, v0, Lk01/p;->z:Lk01/y;

    .line 76
    .line 77
    sget-object v2, Lk01/b;->k:Lk01/b;

    .line 78
    .line 79
    invoke-virtual {p0, v1, v2}, Lk01/y;->j(ILk01/b;)V

    .line 80
    .line 81
    .line 82
    monitor-enter v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 83
    :try_start_1
    iget-object p0, v0, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 84
    .line 85
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-interface {p0, v1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    .line 91
    .line 92
    :try_start_2
    monitor-exit v0

    .line 93
    goto :goto_0

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    monitor-exit v0

    .line 96
    throw p0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 97
    :catch_0
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object p0

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
