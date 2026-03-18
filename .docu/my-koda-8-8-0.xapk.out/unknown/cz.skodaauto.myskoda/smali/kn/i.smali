.class public final Lkn/i;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:J

.field public final synthetic g:F


# direct methods
.method public constructor <init>(JF)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lkn/i;->f:J

    .line 2
    .line 3
    iput p3, p0, Lkn/i;->g:F

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
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
    const-string p1, "$this$drawBehind"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-wide v1, p0, Lkn/i;->f:J

    .line 10
    .line 11
    iget p0, p0, Lkn/i;->g:F

    .line 12
    .line 13
    invoke-static {v1, v2, p0}, Le3/s;->b(JF)J

    .line 14
    .line 15
    .line 16
    move-result-wide v1

    .line 17
    const/4 v9, 0x0

    .line 18
    const/16 v10, 0x7e

    .line 19
    .line 20
    const-wide/16 v3, 0x0

    .line 21
    .line 22
    const-wide/16 v5, 0x0

    .line 23
    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v8, 0x0

    .line 26
    invoke-static/range {v0 .. v10}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method
