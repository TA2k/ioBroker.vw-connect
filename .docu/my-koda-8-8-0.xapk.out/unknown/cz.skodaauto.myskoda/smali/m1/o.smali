.class public final Lm1/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ll2/g1;

.field public final c:Ll2/g1;

.field public d:Z

.field public e:Ljava/lang/Object;

.field public final f:Lo1/g0;


# direct methods
.method public constructor <init>(III)V
    .locals 1

    .line 1
    iput p3, p0, Lm1/o;->a:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance p3, Ll2/g1;

    .line 10
    .line 11
    invoke-direct {p3, p1}, Ll2/g1;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object p3, p0, Lm1/o;->b:Ll2/g1;

    .line 15
    .line 16
    new-instance p3, Ll2/g1;

    .line 17
    .line 18
    invoke-direct {p3, p2}, Ll2/g1;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object p3, p0, Lm1/o;->c:Ll2/g1;

    .line 22
    .line 23
    new-instance p2, Lo1/g0;

    .line 24
    .line 25
    const/16 p3, 0x1e

    .line 26
    .line 27
    const/16 v0, 0x64

    .line 28
    .line 29
    invoke-direct {p2, p1, p3, v0}, Lo1/g0;-><init>(III)V

    .line 30
    .line 31
    .line 32
    iput-object p2, p0, Lm1/o;->f:Lo1/g0;

    .line 33
    .line 34
    return-void

    .line 35
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 36
    .line 37
    .line 38
    new-instance p3, Ll2/g1;

    .line 39
    .line 40
    invoke-direct {p3, p1}, Ll2/g1;-><init>(I)V

    .line 41
    .line 42
    .line 43
    iput-object p3, p0, Lm1/o;->b:Ll2/g1;

    .line 44
    .line 45
    new-instance p3, Ll2/g1;

    .line 46
    .line 47
    invoke-direct {p3, p2}, Ll2/g1;-><init>(I)V

    .line 48
    .line 49
    .line 50
    iput-object p3, p0, Lm1/o;->c:Ll2/g1;

    .line 51
    .line 52
    new-instance p2, Lo1/g0;

    .line 53
    .line 54
    const/16 p3, 0x5a

    .line 55
    .line 56
    const/16 v0, 0xc8

    .line 57
    .line 58
    invoke-direct {p2, p1, p3, v0}, Lo1/g0;-><init>(III)V

    .line 59
    .line 60
    .line 61
    iput-object p2, p0, Lm1/o;->f:Lo1/g0;

    .line 62
    .line 63
    return-void

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(II)V
    .locals 2

    .line 1
    iget v0, p0, Lm1/o;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    int-to-float v0, p1

    .line 7
    const/4 v1, 0x0

    .line 8
    cmpl-float v0, v0, v1

    .line 9
    .line 10
    if-ltz v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string v0, "Index should be non-negative"

    .line 14
    .line 15
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :goto_0
    iget-object v0, p0, Lm1/o;->b:Ll2/g1;

    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ll2/g1;->p(I)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lm1/o;->f:Lo1/g0;

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Lo1/g0;->a(I)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lm1/o;->c:Ll2/g1;

    .line 29
    .line 30
    invoke-virtual {p0, p2}, Ll2/g1;->p(I)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_0
    int-to-float v0, p1

    .line 35
    const/4 v1, 0x0

    .line 36
    cmpl-float v0, v0, v1

    .line 37
    .line 38
    if-ltz v0, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v1, "Index should be non-negative ("

    .line 44
    .line 45
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const/16 v1, 0x29

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    :goto_1
    iget-object v0, p0, Lm1/o;->b:Ll2/g1;

    .line 64
    .line 65
    invoke-virtual {v0, p1}, Ll2/g1;->p(I)V

    .line 66
    .line 67
    .line 68
    iget-object v0, p0, Lm1/o;->f:Lo1/g0;

    .line 69
    .line 70
    invoke-virtual {v0, p1}, Lo1/g0;->a(I)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lm1/o;->c:Ll2/g1;

    .line 74
    .line 75
    invoke-virtual {p0, p2}, Ll2/g1;->p(I)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
