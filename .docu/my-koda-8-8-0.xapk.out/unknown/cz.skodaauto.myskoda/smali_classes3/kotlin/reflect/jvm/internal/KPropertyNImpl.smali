.class public Lkotlin/reflect/jvm/internal/KPropertyNImpl;
.super Lkotlin/reflect/jvm/internal/KPropertyImpl;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Ljava/lang/Object;",
        ">",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl<",
        "TV;>;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0010\u0018\u0000*\u0006\u0008\u0000\u0010\u0001 \u00012\u0008\u0012\u0004\u0012\u00028\u00000\u0002:\u0001\u0010B\u0019\u0008\u0016\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008R \u0010\u000b\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\n0\t8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000b\u0010\u000cR\u001a\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00028\u00000\n8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\r\u0010\u000e\u00a8\u0006\u0011"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl;",
        "V",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl;",
        "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;",
        "container",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;",
        "descriptor",
        "<init>",
        "(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;)V",
        "Llx0/i;",
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;",
        "_getter",
        "Llx0/i;",
        "getGetter",
        "()Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;",
        "getter",
        "Getter",
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
.field private final _getter:Llx0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llx0/i;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;)V
    .locals 1

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "descriptor"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Lkotlin/reflect/jvm/internal/KPropertyImpl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Llx0/j;->e:Llx0/j;

    .line 15
    .line 16
    new-instance p2, Lkotlin/reflect/jvm/internal/KPropertyNImpl$$Lambda$0;

    .line 17
    .line 18
    invoke-direct {p2, p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl$$Lambda$0;-><init>(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KPropertyNImpl;->_getter:Llx0/i;

    .line 26
    .line 27
    return-void
.end method

.method private static final _getter$lambda$0(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;-><init>(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static synthetic accessor$KPropertyNImpl$lambda0(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl;->_getter$lambda$0(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public bridge synthetic getGetter()Lhy0/s;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl;->getGetter()Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getGetter()Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl;->getGetter()Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;

    move-result-object p0

    return-object p0
.end method

.method public getGetter()Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter<",
            "TV;>;"
        }
    .end annotation

    .line 3
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KPropertyNImpl;->_getter:Llx0/i;

    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;

    return-object p0
.end method
