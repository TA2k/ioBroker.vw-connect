.class public final Ld01/n0;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ld01/d0;

.field public final synthetic b:Lu01/i;


# direct methods
.method public constructor <init>(Ld01/d0;Lu01/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld01/n0;->a:Ld01/d0;

    .line 5
    .line 6
    iput-object p2, p0, Ld01/n0;->b:Lu01/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final contentLength()J
    .locals 2

    .line 1
    iget-object p0, p0, Ld01/n0;->b:Lu01/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    int-to-long v0, p0

    .line 8
    return-wide v0
.end method

.method public final contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/n0;->a:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeTo(Lu01/g;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/n0;->b:Lu01/i;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Lu01/g;->t(Lu01/i;)Lu01/g;

    .line 4
    .line 5
    .line 6
    return-void
.end method
