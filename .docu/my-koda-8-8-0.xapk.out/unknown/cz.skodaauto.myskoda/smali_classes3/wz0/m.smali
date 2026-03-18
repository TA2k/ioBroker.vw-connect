.class public final Lwz0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Luz0/w;

.field public b:Z


# direct methods
.method public constructor <init>(Lsz0/g;)V
    .locals 9

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Luz0/w;

    .line 10
    .line 11
    new-instance v1, Lth/b;

    .line 12
    .line 13
    const/4 v7, 0x0

    .line 14
    const/16 v8, 0x8

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    const-class v4, Lwz0/m;

    .line 18
    .line 19
    const-string v5, "readIfAbsent"

    .line 20
    .line 21
    const-string v6, "readIfAbsent(Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z"

    .line 22
    .line 23
    move-object v3, p0

    .line 24
    invoke-direct/range {v1 .. v8}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, p1, v1}, Luz0/w;-><init>(Lsz0/g;Lth/b;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, v3, Lwz0/m;->a:Luz0/w;

    .line 31
    .line 32
    return-void
.end method
