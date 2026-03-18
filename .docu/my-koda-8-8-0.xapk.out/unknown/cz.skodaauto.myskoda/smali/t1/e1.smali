.class public final synthetic Lt1/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/h1;


# direct methods
.method public synthetic constructor <init>(Lt1/h1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt1/e1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/e1;->e:Lt1/h1;

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
    iget v0, p0, Lt1/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt1/e1;->e:Lt1/h1;

    .line 7
    .line 8
    iget-object p0, p0, Lt1/h1;->a:Ll2/f1;

    .line 9
    .line 10
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    const/4 v0, 0x0

    .line 15
    cmpl-float p0, p0, v0

    .line 16
    .line 17
    if-lez p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_0
    iget-object p0, p0, Lt1/e1;->e:Lt1/h1;

    .line 28
    .line 29
    iget-object v0, p0, Lt1/h1;->a:Ll2/f1;

    .line 30
    .line 31
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object p0, p0, Lt1/h1;->b:Ll2/f1;

    .line 36
    .line 37
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    cmpg-float p0, v0, p0

    .line 42
    .line 43
    if-gez p0, :cond_1

    .line 44
    .line 45
    const/4 p0, 0x1

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/4 p0, 0x0

    .line 48
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
