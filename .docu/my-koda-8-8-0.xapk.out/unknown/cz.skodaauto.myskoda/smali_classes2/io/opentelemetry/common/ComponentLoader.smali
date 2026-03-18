.class public interface abstract Lio/opentelemetry/common/ComponentLoader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static forClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/common/ComponentLoader;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/common/ServiceLoaderComponentLoader;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/common/ServiceLoaderComponentLoader;-><init>(Ljava/lang/ClassLoader;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract load(Ljava/lang/Class;)Ljava/lang/Iterable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Class<",
            "TT;>;)",
            "Ljava/lang/Iterable<",
            "TT;>;"
        }
    .end annotation
.end method
