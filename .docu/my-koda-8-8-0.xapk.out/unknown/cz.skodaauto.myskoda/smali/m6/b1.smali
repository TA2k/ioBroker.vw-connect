.class public final Lm6/b1;
.super Ljava/io/OutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/io/FileOutputStream;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lm6/b1;->d:I

    .line 2
    invoke-direct {p0}, Ljava/io/OutputStream;-><init>()V

    iput-object p1, p0, Lm6/b1;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lu01/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm6/b1;->d:I

    iput-object p1, p0, Lm6/b1;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/io/OutputStream;-><init>()V

    return-void
.end method

.method private final a()V
    .locals 0

    .line 1
    return-void
.end method

.method private final b()V
    .locals 0

    .line 1
    return-void
.end method

.method private final d()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget v0, p0, Lm6/b1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lu01/a0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lu01/a0;->close()V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final flush()V
    .locals 1

    .line 1
    iget v0, p0, Lm6/b1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lu01/a0;

    .line 9
    .line 10
    iget-boolean v0, p0, Lu01/a0;->f:Z

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lu01/a0;->flush()V

    .line 15
    .line 16
    .line 17
    :cond_0
    :pswitch_0
    return-void

    .line 18
    :pswitch_1
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ljava/io/FileOutputStream;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/io/OutputStream;->flush()V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lm6/b1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lu01/a0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ".outputStream()"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lu01/f;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, ".outputStream()"

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final write(I)V
    .locals 1

    iget v0, p0, Lm6/b1;->d:I

    packed-switch v0, :pswitch_data_0

    .line 2
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Lu01/a0;

    iget-boolean v0, p0, Lu01/a0;->f:Z

    if-nez v0, :cond_0

    .line 3
    iget-object v0, p0, Lu01/a0;->e:Lu01/f;

    int-to-byte p1, p1

    .line 4
    invoke-virtual {v0, p1}, Lu01/f;->h0(I)V

    .line 5
    invoke-virtual {p0}, Lu01/a0;->a()Lu01/g;

    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/io/IOException;

    const-string p1, "closed"

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 7
    :pswitch_0
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Lu01/f;

    invoke-virtual {p0, p1}, Lu01/f;->h0(I)V

    return-void

    .line 8
    :pswitch_1
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Ljava/io/FileOutputStream;

    invoke-virtual {p0, p1}, Ljava/io/FileOutputStream;->write(I)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public write([B)V
    .locals 1

    iget v0, p0, Lm6/b1;->d:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Ljava/io/OutputStream;->write([B)V

    return-void

    :pswitch_0
    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Ljava/io/FileOutputStream;

    invoke-virtual {p0, p1}, Ljava/io/FileOutputStream;->write([B)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final write([BII)V
    .locals 1

    iget v0, p0, Lm6/b1;->d:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Lu01/a0;

    iget-boolean v0, p0, Lu01/a0;->f:Z

    if-nez v0, :cond_0

    .line 10
    iget-object v0, p0, Lu01/a0;->e:Lu01/f;

    .line 11
    invoke-virtual {v0, p1, p2, p3}, Lu01/f;->write([BII)V

    .line 12
    invoke-virtual {p0}, Lu01/a0;->a()Lu01/g;

    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/io/IOException;

    const-string p1, "closed"

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 14
    :pswitch_0
    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Lu01/f;

    invoke-virtual {p0, p1, p2, p3}, Lu01/f;->write([BII)V

    return-void

    .line 16
    :pswitch_1
    const-string v0, "bytes"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    iget-object p0, p0, Lm6/b1;->e:Ljava/lang/Object;

    check-cast p0, Ljava/io/FileOutputStream;

    invoke-virtual {p0, p1, p2, p3}, Ljava/io/FileOutputStream;->write([BII)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
