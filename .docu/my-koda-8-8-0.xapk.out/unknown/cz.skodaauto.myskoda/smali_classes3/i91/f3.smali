.class public final synthetic Li91/f3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:F

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(JFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Li91/f3;->d:F

    .line 5
    .line 6
    iput p4, p0, Li91/f3;->e:F

    .line 7
    .line 8
    iput-wide p1, p0, Li91/f3;->f:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string p1, "$this$Canvas"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li91/f3;->d:F

    .line 10
    .line 11
    iget v1, p0, Li91/f3;->e:F

    .line 12
    .line 13
    sub-float/2addr p1, v1

    .line 14
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const/high16 v2, 0x40000000    # 2.0f

    .line 19
    .line 20
    div-float v3, p1, v2

    .line 21
    .line 22
    new-instance v4, Lg3/h;

    .line 23
    .line 24
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    const/4 v9, 0x0

    .line 29
    const/16 v10, 0x1e

    .line 30
    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v7, 0x0

    .line 33
    const/4 v8, 0x0

    .line 34
    invoke-direct/range {v4 .. v10}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 35
    .line 36
    .line 37
    const-wide/16 v1, 0x0

    .line 38
    .line 39
    const/16 v7, 0x6c

    .line 40
    .line 41
    iget-wide p0, p0, Li91/f3;->f:J

    .line 42
    .line 43
    move-object v6, v4

    .line 44
    move-wide v4, v1

    .line 45
    move-wide v1, p0

    .line 46
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0
.end method
