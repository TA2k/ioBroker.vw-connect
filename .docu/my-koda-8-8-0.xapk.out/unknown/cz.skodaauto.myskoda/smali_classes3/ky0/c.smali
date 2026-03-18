.class public final Lky0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;
.implements Lky0/d;


# instance fields
.field public final synthetic a:I

.field public final b:Lky0/j;

.field public final c:I


# direct methods
.method public constructor <init>(Lky0/j;II)V
    .locals 0

    .line 1
    iput p3, p0, Lky0/c;->a:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p3, "sequence"

    .line 7
    .line 8
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lky0/c;->b:Lky0/j;

    .line 15
    .line 16
    iput p2, p0, Lky0/c;->c:I

    .line 17
    .line 18
    if-ltz p2, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string p1, "count must be non-negative, but was "

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const/16 p1, 0x2e

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p1

    .line 50
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    .line 52
    .line 53
    iput-object p1, p0, Lky0/c;->b:Lky0/j;

    .line 54
    .line 55
    iput p2, p0, Lky0/c;->c:I

    .line 56
    .line 57
    if-ltz p2, :cond_1

    .line 58
    .line 59
    return-void

    .line 60
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string p1, "count must be non-negative, but was "

    .line 63
    .line 64
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const/16 p1, 0x2e

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p1

    .line 89
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(I)Lky0/j;
    .locals 2

    .line 1
    iget v0, p0, Lky0/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lky0/c;->c:I

    .line 7
    .line 8
    if-lt p1, v0, :cond_0

    .line 9
    .line 10
    sget-object p0, Lky0/e;->a:Lky0/e;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance v1, Lky0/r;

    .line 14
    .line 15
    iget-object p0, p0, Lky0/c;->b:Lky0/j;

    .line 16
    .line 17
    invoke-direct {v1, p0, p1, v0}, Lky0/r;-><init>(Lky0/j;II)V

    .line 18
    .line 19
    .line 20
    move-object p0, v1

    .line 21
    :goto_0
    return-object p0

    .line 22
    :pswitch_0
    iget v0, p0, Lky0/c;->c:I

    .line 23
    .line 24
    add-int/2addr v0, p1

    .line 25
    if-gez v0, :cond_1

    .line 26
    .line 27
    new-instance v0, Lky0/c;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-direct {v0, p0, p1, v1}, Lky0/c;-><init>(Lky0/j;II)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    new-instance p1, Lky0/c;

    .line 35
    .line 36
    iget-object p0, p0, Lky0/c;->b:Lky0/j;

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-direct {p1, p0, v0, v1}, Lky0/c;-><init>(Lky0/j;II)V

    .line 40
    .line 41
    .line 42
    move-object v0, p1

    .line 43
    :goto_1
    return-object v0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(I)Lky0/j;
    .locals 2

    .line 1
    iget v0, p0, Lky0/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lky0/c;->c:I

    .line 7
    .line 8
    if-lt p1, v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance v0, Lky0/c;

    .line 12
    .line 13
    iget-object p0, p0, Lky0/c;->b:Lky0/j;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, p0, p1, v1}, Lky0/c;-><init>(Lky0/j;II)V

    .line 17
    .line 18
    .line 19
    move-object p0, v0

    .line 20
    :goto_0
    return-object p0

    .line 21
    :pswitch_0
    iget v0, p0, Lky0/c;->c:I

    .line 22
    .line 23
    add-int v1, v0, p1

    .line 24
    .line 25
    if-gez v1, :cond_1

    .line 26
    .line 27
    new-instance v0, Lky0/c;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-direct {v0, p0, p1, v1}, Lky0/c;-><init>(Lky0/j;II)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    new-instance p1, Lky0/r;

    .line 35
    .line 36
    iget-object p0, p0, Lky0/c;->b:Lky0/j;

    .line 37
    .line 38
    invoke-direct {p1, p0, v0, v1}, Lky0/r;-><init>(Lky0/j;II)V

    .line 39
    .line 40
    .line 41
    move-object v0, p1

    .line 42
    :goto_1
    return-object v0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    iget v0, p0, Lky0/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/b;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Lky0/b;-><init>(Lky0/c;B)V

    .line 10
    .line 11
    .line 12
    return-object v0

    .line 13
    :pswitch_0
    new-instance v0, Lky0/b;

    .line 14
    .line 15
    invoke-direct {v0, p0}, Lky0/b;-><init>(Lky0/c;)V

    .line 16
    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
