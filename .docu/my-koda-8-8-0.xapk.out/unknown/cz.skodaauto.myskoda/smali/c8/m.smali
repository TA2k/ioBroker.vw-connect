.class public final Lc8/m;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:I

.field public final e:Z

.field public final f:Lt7/o;


# direct methods
.method public constructor <init>(ILt7/o;Z)V
    .locals 1

    .line 1
    const-string v0, "AudioTrack write failed: "

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iput-boolean p3, p0, Lc8/m;->e:Z

    .line 11
    .line 12
    iput p1, p0, Lc8/m;->d:I

    .line 13
    .line 14
    iput-object p2, p0, Lc8/m;->f:Lt7/o;

    .line 15
    .line 16
    return-void
.end method
