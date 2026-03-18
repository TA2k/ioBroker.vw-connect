.class public final Li9/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Li9/q;

.field public final b:Li9/t;

.field public final c:Lo8/i0;

.field public final d:Lo8/j0;

.field public e:I


# direct methods
.method public constructor <init>(Li9/q;Li9/t;Lo8/i0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li9/l;->a:Li9/q;

    .line 5
    .line 6
    iput-object p2, p0, Li9/l;->b:Li9/t;

    .line 7
    .line 8
    iput-object p3, p0, Li9/l;->c:Lo8/i0;

    .line 9
    .line 10
    iget-object p1, p1, Li9/q;->g:Lt7/o;

    .line 11
    .line 12
    iget-object p1, p1, Lt7/o;->n:Ljava/lang/String;

    .line 13
    .line 14
    const-string p2, "audio/true-hd"

    .line 15
    .line 16
    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    new-instance p1, Lo8/j0;

    .line 23
    .line 24
    invoke-direct {p1}, Lo8/j0;-><init>()V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p1, 0x0

    .line 29
    :goto_0
    iput-object p1, p0, Li9/l;->d:Lo8/j0;

    .line 30
    .line 31
    return-void
.end method
