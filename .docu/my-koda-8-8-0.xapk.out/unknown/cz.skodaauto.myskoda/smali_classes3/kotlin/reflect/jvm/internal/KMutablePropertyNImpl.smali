.class public final Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;
.super Lkotlin/reflect/jvm/internal/KPropertyNImpl;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/o;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Ljava/lang/Object;",
        ">",
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl<",
        "TV;>;",
        "Lhy0/o;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0000\u0018\u0000*\u0004\u0008\u0000\u0010\u00012\u0008\u0012\u0004\u0012\u00028\u00000\u00022\u0008\u0012\u0004\u0012\u00028\u00000\u0003:\u0001\u0011B\u0019\u0008\u0016\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tR \u0010\u000c\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\u000b0\n8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u0010\rR\u001a\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u000b8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0012"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;",
        "V",
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl;",
        "Lhy0/o;",
        "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;",
        "container",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;",
        "descriptor",
        "<init>",
        "(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;)V",
        "Llx0/i;",
        "Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;",
        "_setter",
        "Llx0/i;",
        "getSetter",
        "()Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;",
        "setter",
        "Setter",
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
.field private final _setter:Llx0/i;
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
    invoke-direct {p0, p1, p2}, Lkotlin/reflect/jvm/internal/KPropertyNImpl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Llx0/j;->e:Llx0/j;

    .line 15
    .line 16
    new-instance p2, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$$Lambda$0;

    .line 17
    .line 18
    invoke-direct {p2, p0}, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$$Lambda$0;-><init>(Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;->_setter:Llx0/i;

    .line 26
    .line 27
    return-void
.end method

.method private static final _setter$lambda$0(Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;)Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;-><init>(Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static synthetic accessor$KMutablePropertyNImpl$lambda0(Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;)Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;->_setter$lambda$0(Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;)Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public bridge synthetic getSetter()Lhy0/h;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;->getSetter()Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;

    move-result-object p0

    return-object p0
.end method

.method public getSetter()Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter<",
            "TV;>;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl;->_setter:Llx0/i;

    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lkotlin/reflect/jvm/internal/KMutablePropertyNImpl$Setter;

    return-object p0
.end method
