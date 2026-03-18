.class public final Ls51/b;
.super Ljava/lang/Throwable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le91/a;


# instance fields
.field public final d:Le91/b;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Le91/b;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Throwable;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls51/b;->d:Le91/b;

    .line 5
    .line 6
    iput-object p2, p0, Ls51/b;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ls51/b;->f:Ljava/lang/Throwable;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final getCause()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Ls51/b;->f:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getContext()Le91/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ls51/b;->d:Le91/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ls51/b;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
