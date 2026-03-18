.class public final Lwn/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwn/b;


# static fields
.field public static final f:Ljava/util/logging/Logger;


# instance fields
.field public final a:Lrn/i;

.field public final b:Ljava/util/concurrent/Executor;

.field public final c:Lsn/d;

.field public final d:Lyn/d;

.field public final e:Lzn/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lrn/r;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lwn/a;->f:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Lsn/d;Lrn/i;Lyn/d;Lzn/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwn/a;->b:Ljava/util/concurrent/Executor;

    .line 5
    .line 6
    iput-object p2, p0, Lwn/a;->c:Lsn/d;

    .line 7
    .line 8
    iput-object p3, p0, Lwn/a;->a:Lrn/i;

    .line 9
    .line 10
    iput-object p4, p0, Lwn/a;->d:Lyn/d;

    .line 11
    .line 12
    iput-object p5, p0, Lwn/a;->e:Lzn/c;

    .line 13
    .line 14
    return-void
.end method
