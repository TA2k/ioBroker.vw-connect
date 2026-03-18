.class public final Ll2/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public final e:Ll2/f2;

.field public final f:I

.field public g:I

.field public h:I


# direct methods
.method public constructor <init>(Ll2/f2;II)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ll2/o0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll2/o0;->e:Ll2/f2;

    iput p3, p0, Ll2/o0;->f:I

    .line 2
    iput p2, p0, Ll2/o0;->g:I

    .line 3
    iget p2, p1, Ll2/f2;->k:I

    .line 4
    iput p2, p0, Ll2/o0;->h:I

    .line 5
    iget-boolean p0, p1, Ll2/f2;->j:Z

    if-eqz p0, :cond_0

    .line 6
    invoke-static {}, Ll2/h2;->f()V

    :cond_0
    return-void
.end method

.method public constructor <init>(Ll2/f2;ILl2/p0;Ll2/b;)V
    .locals 0

    const/4 p3, 0x1

    iput p3, p0, Ll2/o0;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Ll2/o0;->e:Ll2/f2;

    .line 9
    iput p2, p0, Ll2/o0;->f:I

    .line 10
    iget p1, p1, Ll2/f2;->k:I

    .line 11
    iput p1, p0, Ll2/o0;->g:I

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Ll2/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    throw p0

    .line 8
    :pswitch_0
    iget v0, p0, Ll2/o0;->g:I

    .line 9
    .line 10
    iget p0, p0, Ll2/o0;->f:I

    .line 11
    .line 12
    if-ge v0, p0, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    return p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ll2/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    throw p0

    .line 8
    :pswitch_0
    iget-object v0, p0, Ll2/o0;->e:Ll2/f2;

    .line 9
    .line 10
    iget v1, v0, Ll2/f2;->k:I

    .line 11
    .line 12
    iget v2, p0, Ll2/o0;->h:I

    .line 13
    .line 14
    if-eq v1, v2, :cond_0

    .line 15
    .line 16
    invoke-static {}, Ll2/h2;->f()V

    .line 17
    .line 18
    .line 19
    :cond_0
    iget v1, p0, Ll2/o0;->g:I

    .line 20
    .line 21
    iget-object v3, v0, Ll2/f2;->d:[I

    .line 22
    .line 23
    invoke-static {v1, v3}, Ll2/h2;->a(I[I)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    add-int/2addr v3, v1

    .line 28
    iput v3, p0, Ll2/o0;->g:I

    .line 29
    .line 30
    new-instance p0, Ll2/g2;

    .line 31
    .line 32
    invoke-direct {p0, v0, v1, v2}, Ll2/g2;-><init>(Ll2/f2;II)V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 1

    .line 1
    iget p0, p0, Ll2/o0;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string v0, "Operation is not supported for read-only collection"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string v0, "Operation is not supported for read-only collection"

    .line 17
    .line 18
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
