.class public final Lin/y1;
.super Llp/pa;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:F

.field public final synthetic b:Lin/z1;


# direct methods
.method public constructor <init>(Lin/z1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lin/y1;->b:Lin/z1;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lin/y1;->a:F

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final d(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget v0, p0, Lin/y1;->a:F

    .line 2
    .line 3
    iget-object v1, p0, Lin/y1;->b:Lin/z1;

    .line 4
    .line 5
    iget-object v1, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lin/x1;

    .line 8
    .line 9
    iget-object v1, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 10
    .line 11
    invoke-virtual {v1, p1}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    add-float/2addr p1, v0

    .line 16
    iput p1, p0, Lin/y1;->a:F

    .line 17
    .line 18
    return-void
.end method
