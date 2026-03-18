.class public final Lv9/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv9/h;

.field public final b:Lw7/u;

.field public final c:Lm9/f;

.field public d:Z

.field public e:Z

.field public f:Z

.field public g:J


# direct methods
.method public constructor <init>(Lv9/h;Lw7/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/y;->a:Lv9/h;

    .line 5
    .line 6
    iput-object p2, p0, Lv9/y;->b:Lw7/u;

    .line 7
    .line 8
    new-instance p1, Lm9/f;

    .line 9
    .line 10
    const/16 p2, 0x40

    .line 11
    .line 12
    new-array v0, p2, [B

    .line 13
    .line 14
    invoke-direct {p1, p2, v0}, Lm9/f;-><init>(I[B)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lv9/y;->c:Lm9/f;

    .line 18
    .line 19
    return-void
.end method
