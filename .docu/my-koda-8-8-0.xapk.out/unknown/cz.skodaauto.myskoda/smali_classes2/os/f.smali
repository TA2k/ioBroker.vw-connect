.class public final Los/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Los/k;


# static fields
.field public static final f:Lgv/a;


# instance fields
.field public final d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgv/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Los/f;->f:Lgv/a;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lss/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Los/f;->d:Ljava/lang/Object;

    .line 3
    sget-object p1, Los/f;->f:Lgv/a;

    iput-object p1, p0, Los/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>([B[I)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Los/f;->d:Ljava/lang/Object;

    iput-object p2, p0, Los/f;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public d(Los/j;I)V
    .locals 3

    .line 1
    iget-object v0, p0, Los/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [I

    .line 4
    .line 5
    :try_start_0
    iget-object p0, p0, Los/f;->d:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, [B

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    aget v2, v0, v1

    .line 11
    .line 12
    invoke-virtual {p1, p0, v2, p2}, Los/j;->read([BII)I

    .line 13
    .line 14
    .line 15
    aget p0, v0, v1

    .line 16
    .line 17
    add-int/2addr p0, p2

    .line 18
    aput p0, v0, v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    .line 26
    .line 27
    .line 28
    throw p0
.end method
