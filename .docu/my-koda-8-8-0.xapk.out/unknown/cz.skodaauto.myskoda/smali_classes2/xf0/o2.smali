.class public final synthetic Lxf0/o2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Le3/f;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:Le3/f;


# direct methods
.method public synthetic constructor <init>(FLe3/f;JFFLe3/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/o2;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/o2;->e:Le3/f;

    .line 7
    .line 8
    iput-wide p3, p0, Lxf0/o2;->f:J

    .line 9
    .line 10
    iput p5, p0, Lxf0/o2;->g:F

    .line 11
    .line 12
    iput p6, p0, Lxf0/o2;->h:F

    .line 13
    .line 14
    iput-object p7, p0, Lxf0/o2;->i:Le3/f;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

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
    iget v1, p0, Lxf0/o2;->d:F

    .line 10
    .line 11
    iget-object v2, p0, Lxf0/o2;->e:Le3/f;

    .line 12
    .line 13
    iget-wide v3, p0, Lxf0/o2;->f:J

    .line 14
    .line 15
    iget v5, p0, Lxf0/o2;->g:F

    .line 16
    .line 17
    invoke-static/range {v0 .. v5}, Lxf0/r2;->h(Lg3/d;FLe3/f;JF)V

    .line 18
    .line 19
    .line 20
    iget v1, p0, Lxf0/o2;->h:F

    .line 21
    .line 22
    iget-object v2, p0, Lxf0/o2;->i:Le3/f;

    .line 23
    .line 24
    invoke-static/range {v0 .. v5}, Lxf0/r2;->h(Lg3/d;FLe3/f;JF)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0
.end method
