.class public final synthetic Le1/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le1/k1;


# direct methods
.method public synthetic constructor <init>(Le1/k1;I)V
    .locals 0

    .line 1
    iput p2, p0, Le1/j1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le1/j1;->e:Le1/k1;

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
    iget v0, p0, Le1/j1;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Le1/j1;->e:Le1/k1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Le1/k1;->r:Le1/n1;

    .line 9
    .line 10
    iget-object p0, p0, Le1/n1;->d:Ll2/g1;

    .line 11
    .line 12
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    :goto_0
    int-to-float p0, p0

    .line 17
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Le1/k1;->r:Le1/n1;

    .line 23
    .line 24
    iget-object p0, p0, Le1/n1;->a:Ll2/g1;

    .line 25
    .line 26
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    goto :goto_0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
