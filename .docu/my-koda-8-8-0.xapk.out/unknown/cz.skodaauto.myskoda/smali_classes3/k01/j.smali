.class public final synthetic Lk01/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Luz0/x;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lk01/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lk01/j;->e:I

    iput-object p2, p0, Lk01/j;->f:Ljava/lang/Object;

    iput-object p3, p0, Lk01/j;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lk01/p;ILk01/b;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lk01/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk01/j;->f:Ljava/lang/Object;

    iput p2, p0, Lk01/j;->e:I

    iput-object p3, p0, Lk01/j;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lk01/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk01/j;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/lang/String;

    .line 9
    .line 10
    iget-object v1, p0, Lk01/j;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Luz0/x;

    .line 13
    .line 14
    iget p0, p0, Lk01/j;->e:I

    .line 15
    .line 16
    new-array v2, p0, [Lsz0/g;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, p0, :cond_0

    .line 21
    .line 22
    new-instance v5, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const/16 v6, 0x2e

    .line 31
    .line 32
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v6, v1, Luz0/d1;->e:[Ljava/lang/String;

    .line 36
    .line 37
    aget-object v6, v6, v4

    .line 38
    .line 39
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    sget-object v6, Lsz0/k;->e:Lsz0/k;

    .line 47
    .line 48
    new-array v7, v3, [Lsz0/g;

    .line 49
    .line 50
    invoke-static {v5, v6, v7}, Lkp/x8;->e(Ljava/lang/String;Lkp/y8;[Lsz0/g;)Lsz0/h;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    aput-object v5, v2, v4

    .line 55
    .line 56
    add-int/lit8 v4, v4, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    return-object v2

    .line 60
    :pswitch_0
    iget-object v0, p0, Lk01/j;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lk01/p;

    .line 63
    .line 64
    iget v1, p0, Lk01/j;->e:I

    .line 65
    .line 66
    iget-object p0, p0, Lk01/j;->g:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lk01/b;

    .line 69
    .line 70
    :try_start_0
    iget-object v2, v0, Lk01/p;->z:Lk01/y;

    .line 71
    .line 72
    invoke-virtual {v2, v1, p0}, Lk01/y;->j(ILk01/b;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :catch_0
    move-exception p0

    .line 77
    sget-object v1, Lk01/b;->g:Lk01/b;

    .line 78
    .line 79
    invoke-virtual {v0, v1, v1, p0}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 80
    .line 81
    .line 82
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
