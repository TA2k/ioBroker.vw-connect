.class final Lkotlin/reflect/jvm/internal/ComputableClassValue;
.super Ljava/lang/ClassValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/ClassValue<",
        "Ljava/lang/ref/SoftReference<",
        "TV;>;>;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\n\u0008\u0003\u0018\u0000*\u0004\u0008\u0000\u0010\u00012\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\u00030\u0002B\u001f\u0012\u0016\u0010\u0006\u001a\u0012\u0012\u0008\u0012\u0006\u0012\u0002\u0008\u00030\u0005\u0012\u0004\u0012\u00028\u00000\u0004\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J!\u0010\n\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u00032\n\u0010\t\u001a\u0006\u0012\u0002\u0008\u00030\u0005H\u0014\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0013\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u0000\u00a2\u0006\u0004\u0008\u000c\u0010\rR$\u0010\u0006\u001a\u0012\u0012\u0008\u0012\u0006\u0012\u0002\u0008\u00030\u0005\u0012\u0004\u0012\u00028\u00000\u00048\u0006X\u0087\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0006\u0010\u000e\u00a8\u0006\u000f"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/ComputableClassValue;",
        "V",
        "Ljava/lang/ClassValue;",
        "Ljava/lang/ref/SoftReference;",
        "Lkotlin/Function1;",
        "Ljava/lang/Class;",
        "compute",
        "<init>",
        "(Lay0/k;)V",
        "type",
        "computeValue",
        "(Ljava/lang/Class;)Ljava/lang/ref/SoftReference;",
        "createNewCopy",
        "()Lkotlin/reflect/jvm/internal/ComputableClassValue;",
        "Lay0/k;",
        "kotlin-reflection"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final compute:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "compute"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/ClassValue;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/ComputableClassValue;->compute:Lay0/k;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge synthetic computeValue(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/ComputableClassValue;->computeValue(Ljava/lang/Class;)Ljava/lang/ref/SoftReference;

    move-result-object p0

    return-object p0
.end method

.method public computeValue(Ljava/lang/Class;)Ljava/lang/ref/SoftReference;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;)",
            "Ljava/lang/ref/SoftReference<",
            "TV;>;"
        }
    .end annotation

    const-string v0, "type"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Ljava/lang/ref/SoftReference;

    iget-object p0, p0, Lkotlin/reflect/jvm/internal/ComputableClassValue;->compute:Lay0/k;

    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/ref/SoftReference;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final createNewCopy()Lkotlin/reflect/jvm/internal/ComputableClassValue;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/ComputableClassValue<",
            "TV;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/ComputableClassValue;

    .line 2
    .line 3
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/ComputableClassValue;->compute:Lay0/k;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/ComputableClassValue;-><init>(Lay0/k;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method
