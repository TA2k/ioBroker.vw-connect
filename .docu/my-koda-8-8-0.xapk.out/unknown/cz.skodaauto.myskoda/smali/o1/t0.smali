.class public final synthetic Lo1/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lo1/u0;


# direct methods
.method public synthetic constructor <init>(Lo1/u0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lo1/t0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo1/t0;->e:Lo1/u0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lo1/t0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lo1/t0;->e:Lo1/u0;

    .line 7
    .line 8
    iget-object v0, p0, Lo1/u0;->s:Lo1/r0;

    .line 9
    .line 10
    invoke-interface {v0}, Lo1/r0;->d()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iget-object p0, p0, Lo1/u0;->s:Lo1/r0;

    .line 15
    .line 16
    invoke-interface {p0}, Lo1/r0;->a()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    sub-int/2addr v0, p0

    .line 21
    int-to-float p0, v0

    .line 22
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_0
    iget-object p0, p0, Lo1/t0;->e:Lo1/u0;

    .line 28
    .line 29
    iget-object p0, p0, Lo1/u0;->s:Lo1/r0;

    .line 30
    .line 31
    invoke-interface {p0}, Lo1/r0;->b()F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    iget-object p0, p0, Lo1/t0;->e:Lo1/u0;

    .line 41
    .line 42
    iget-object p0, p0, Lo1/u0;->s:Lo1/r0;

    .line 43
    .line 44
    invoke-interface {p0}, Lo1/r0;->e()F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
