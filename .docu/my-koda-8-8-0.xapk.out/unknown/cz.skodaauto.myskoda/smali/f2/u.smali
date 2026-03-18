.class public final Lf2/u;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements Lv3/j1;


# instance fields
.field public final synthetic t:I

.field public final u:Li1/l;

.field public final v:Z

.field public final w:F

.field public final x:Le3/t;

.field public y:Lg2/a;


# direct methods
.method public constructor <init>(Li1/l;ZFLe3/t;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf2/u;->t:I

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    iput-object p1, p0, Lf2/u;->u:Li1/l;

    .line 3
    iput-boolean p2, p0, Lf2/u;->v:Z

    .line 4
    iput p3, p0, Lf2/u;->w:F

    .line 5
    iput-object p4, p0, Lf2/u;->x:Le3/t;

    return-void
.end method

.method public constructor <init>(Li1/l;ZLe3/t;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lf2/u;->t:I

    .line 6
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 7
    iput-object p1, p0, Lf2/u;->u:Li1/l;

    .line 8
    iput-boolean p2, p0, Lf2/u;->v:Z

    const/high16 p1, 0x7fc00000    # Float.NaN

    .line 9
    iput p1, p0, Lf2/u;->w:F

    .line 10
    iput-object p3, p0, Lf2/u;->x:Le3/t;

    return-void
.end method


# virtual methods
.method public final O()V
    .locals 2

    .line 1
    iget v0, p0, Lf2/u;->t:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/n4;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Lh2/n4;-><init>(Lf2/u;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    new-instance v0, Lf2/s;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {v0, p0, v1}, Lf2/s;-><init>(Lf2/u;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final P0()V
    .locals 2

    .line 1
    iget v0, p0, Lf2/u;->t:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/n4;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Lh2/n4;-><init>(Lf2/u;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    new-instance v0, Lf2/s;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {v0, p0, v1}, Lf2/s;-><init>(Lf2/u;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
