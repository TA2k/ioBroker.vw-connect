.class public final Lwa/d;
.super Ljava/lang/RuntimeException;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lwa/e;

.field public final e:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Lwa/e;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwa/d;->d:Lwa/e;

    .line 5
    .line 6
    iput-object p2, p0, Lwa/d;->e:Ljava/lang/Throwable;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getCause()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/d;->e:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method
