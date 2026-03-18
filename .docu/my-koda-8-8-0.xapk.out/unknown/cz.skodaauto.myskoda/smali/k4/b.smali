.class public final Lk4/b;
.super Lp5/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Luq/c;Llp/y9;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lk4/b;->e:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lk4/b;->g:Ljava/lang/Object;

    iput-object p2, p0, Lk4/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvy0/l;Lk4/c0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lk4/b;->e:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lk4/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Lk4/b;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final h(I)V
    .locals 4

    .line 1
    iget v0, p0, Lk4/b;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk4/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luq/c;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iput-boolean v1, v0, Luq/c;->n:Z

    .line 12
    .line 13
    iget-object p0, p0, Lk4/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Llp/y9;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Llp/y9;->b(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lk4/b;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lvy0/l;

    .line 24
    .line 25
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    new-instance v2, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v3, "Unable to load font "

    .line 30
    .line 31
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lk4/b;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lk4/c0;

    .line 37
    .line 38
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string p0, " (reason="

    .line 42
    .line 43
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const/16 p0, 0x29

    .line 50
    .line 51
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, v1}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Landroid/graphics/Typeface;)V
    .locals 2

    .line 1
    iget v0, p0, Lk4/b;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk4/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luq/c;

    .line 9
    .line 10
    iget v1, v0, Luq/c;->d:I

    .line 11
    .line 12
    invoke-static {p1, v1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, v0, Luq/c;->p:Landroid/graphics/Typeface;

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, v0, Luq/c;->n:Z

    .line 20
    .line 21
    iget-object p0, p0, Lk4/b;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Llp/y9;

    .line 24
    .line 25
    iget-object p1, v0, Luq/c;->p:Landroid/graphics/Typeface;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    invoke-virtual {p0, p1, v0}, Llp/y9;->c(Landroid/graphics/Typeface;Z)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_0
    iget-object p0, p0, Lk4/b;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Lvy0/l;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
