.class public final Lc8/l;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:I

.field public final e:Z


# direct methods
.method public constructor <init>(IIIIILt7/o;ZLjava/lang/RuntimeException;)V
    .locals 3

    .line 1
    const-string v0, "AudioTrack init failed "

    .line 2
    .line 3
    const-string v1, " Config("

    .line 4
    .line 5
    const-string v2, ", "

    .line 6
    .line 7
    invoke-static {p1, p2, v0, v1, v2}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-static {p2, p3, v2, p4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p3, ") "

    .line 18
    .line 19
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    if-eqz p7, :cond_0

    .line 26
    .line 27
    const-string p3, " (recoverable)"

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const-string p3, ""

    .line 31
    .line 32
    :goto_0
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-direct {p0, p2, p8}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 40
    .line 41
    .line 42
    iput p1, p0, Lc8/l;->d:I

    .line 43
    .line 44
    iput-boolean p7, p0, Lc8/l;->e:Z

    .line 45
    .line 46
    return-void
.end method
