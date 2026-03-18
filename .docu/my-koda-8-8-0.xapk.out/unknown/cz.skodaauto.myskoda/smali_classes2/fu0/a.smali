.class public final Lfu0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhu0/c;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/i;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/4 v1, 0x7

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lfu0/a;->a:Lyy0/q1;

    .line 12
    .line 13
    sget v1, Lmy0/c;->g:I

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 17
    .line 18
    invoke-static {v1, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 19
    .line 20
    .line 21
    move-result-wide v1

    .line 22
    invoke-static {v1, v2}, Lvy0/e0;->O(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide v1

    .line 26
    invoke-static {v0, v1, v2}, Lyy0/u;->o(Lyy0/i;J)Lyy0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Lfu0/a;->b:Lyy0/i;

    .line 31
    .line 32
    return-void
.end method
