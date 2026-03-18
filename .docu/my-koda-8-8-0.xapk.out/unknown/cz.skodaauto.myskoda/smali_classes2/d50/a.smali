.class public final Ld50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf50/r;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;

.field public final c:Lyy0/q1;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    const/4 v1, 0x5

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iput-object v3, p0, Ld50/a;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v4, Lyy0/k1;

    .line 14
    .line 15
    invoke-direct {v4, v3}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 16
    .line 17
    .line 18
    iput-object v4, p0, Ld50/a;->b:Lyy0/k1;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Ld50/a;->c:Lyy0/q1;

    .line 25
    .line 26
    return-void
.end method
